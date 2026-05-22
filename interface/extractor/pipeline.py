"""Rust-style diagnostic orchestration pipeline — single clean path.

Flow:
  parse_log → parse_trace → find error insn → opcode safety conditions
  → monitor (lifecycle) → transition_analyzer (causal chain)
  → derive taxonomy from analysis → build proof events
  → correlate to source → render
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .engine.cfg_builder import TraceCFG, build_cfg
from .bpftool_parser import parse_bpftool_xlated_linum
from .engine.monitor import (
    CarrierLifecycle,
    LifecycleEvent,
    TraceMonitor,
    monitor_carriers,
)
from .engine.opcode_safety import (
    CarrierSpec,
    OpcodeConditionPredicate,
    SafetySchema,
    discover_compatible_carriers,
    evaluate_condition,
    find_violated_condition,
    infer_conditions_from_error_insn,
    infer_safety_schemas,
    instantiate_primary_carrier,
    instantiate_schema,
)
from .engine.slicer import backward_slice
from .engine.transition_analyzer import TransitionAnalyzer, TransitionEffect
from .log_parser import ParsedLog, parse_log
from .reject_info import (
    SpecificRejectInfo,
    extract_specific_contract_mismatch,
    extract_specific_reject_info,
    specific_contract_help,
    specific_contract_note,
)
from .renderer import DiagnosticOutput, render_diagnostic
from .source_correlator import ProofEvent, ProofObligation, SourceSpan, correlate_to_source
from .trace_parser import ParsedTrace, parse_trace


_STRUCTURAL_TAXONOMY_BY_ERROR_ID = {
    "BPFIX-E007": "verifier_limit",
    "BPFIX-E008": "verifier_limit",
    "BPFIX-E009": "environment_or_configuration",
    "BPFIX-E010": "verifier_false_positive",
    "BPFIX-E016": "environment_or_configuration",
    "BPFIX-E018": "verifier_limit",
    "BPFIX-E021": "environment_or_configuration",
    "BPFIX-E022": "environment_or_configuration",
}


@dataclass
class AtomClassification:
    classification: str
    schema: SafetySchema
    primary: CarrierSpec | None
    carrier: CarrierSpec | None = None
    reason: str | None = None
    establish: LifecycleEvent | None = None
    loss: LifecycleEvent | None = None
    reject_evaluation: str | None = None
    lifecycles: dict[str, CarrierLifecycle] | None = None
    backward_slice: Any | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_diagnostic(
    verifier_log: str,
    catalog_path: str | None = None,
    bpftool_xlated: str | None = None,
) -> DiagnosticOutput:
    """Run the full parser → engine → source correlation → renderer pipeline.

    Single path — no fallbacks, no parallel systems, no keyword heuristics.
    """
    # Step 1: parse log (error_id, taxonomy_class, error_line from catalog matching)
    parsed_log = parse_log(verifier_log, catalog_path=catalog_path)

    # Step 2: parse trace (per-instruction abstract state)
    parsed_trace = parse_trace(verifier_log)

    bpftool_source_map = (
        parse_bpftool_xlated_linum(bpftool_xlated) if bpftool_xlated else None
    )

    # Step 3: find the error instruction (explicitly marked is_error=True)
    instructions = list(getattr(parsed_trace, "instructions", []))
    error_insn = next((i for i in instructions if i.is_error), None)
    error_line = parsed_trace.error_line or parsed_log.error_line or ""
    structural_taxonomy_class = _STRUCTURAL_TAXONOMY_BY_ERROR_ID.get(parsed_log.error_id)

    cross_analysis_class: str | None = None
    cross_atom_results: list[AtomClassification] = []
    cross_cfg: TraceCFG | None = None

    if structural_taxonomy_class is None and error_insn is not None:
        schemas = infer_safety_schemas(error_insn)
        cross_cfg = build_cfg(instructions) if instructions else None
        dominators = compute_forward_dominators(cross_cfg) if cross_cfg is not None else {}

        for schema in schemas:
            primary = instantiate_primary_carrier(schema, error_insn)
            if primary is None:
                cross_atom_results.append(AtomClassification(
                    classification="ambiguous",
                    schema=schema,
                    primary=None,
                    reason="no_primary_carrier",
                    reject_evaluation="unknown",
                ))
                continue

            condition = instantiate_schema(schema, primary)
            reject_evaluation = evaluate_condition(condition, error_insn.pre_state)

            if reject_evaluation == "satisfied":
                cross_atom_results.append(AtomClassification(
                    classification="inactive",
                    schema=schema,
                    primary=primary,
                    reject_evaluation=reject_evaluation,
                ))
                continue

            carriers = discover_compatible_carriers(schema, primary, error_insn.pre_state)
            lifecycles = monitor_carriers(schema, carriers, instructions)
            bslice = backward_slice(
                instructions,
                criterion_insn=error_insn.insn_idx,
                criterion_register=primary.register,
                cfg=cross_cfg,
            )
            cross_atom_results.append(classify_atom(
                schema,
                error_insn,
                instructions,
                cross_cfg,
                dominators,
                primary=primary,
                monitoring=lifecycles,
                bslice=bslice,
                reject_evaluation=reject_evaluation,
            ))

        cross_analysis_class = aggregate_atom_classes(
            [result.classification for result in cross_atom_results]
        )

    # Step 4: derive safety conditions from error instruction opcode (ISA-driven, no keywords)
    predicate = None
    if structural_taxonomy_class is None and error_insn is not None:
        conditions = infer_conditions_from_error_insn(error_insn)
        violated = find_violated_condition(error_insn, conditions)
        if violated is not None:
            predicate = OpcodeConditionPredicate(violated)

    # Step 5: run TraceMonitor — find where proof was established and where it was lost
    monitor = TraceMonitor()
    monitor_result = monitor.monitor(predicate, instructions)

    # Step 6: run TransitionAnalyzer — build causal chain of state-degrading transitions
    proof_registers: set[str] = set()
    if predicate is not None:
        proof_registers = set(getattr(predicate, "target_regs", []))
    analyzer = TransitionAnalyzer()
    transition_chain = analyzer.analyze(instructions, proof_registers)

    # Step 7: derive proof_status from analysis results (not keywords)
    if structural_taxonomy_class is not None:
        proof_status = "unknown"
        taxonomy_class = structural_taxonomy_class
    else:
        proof_status = _derive_proof_status(
            monitor_result=monitor_result,
            transition_chain=transition_chain,
            predicate=predicate,
            error_insn=error_insn,
        )
        taxonomy_class = _override_taxonomy_class(
            _derive_taxonomy_class(
                predicate=predicate,
                proof_status=proof_status,
                monitor_result=monitor_result,
                error_insn=error_insn,
                parsed_log=parsed_log,
            ),
            cross_analysis_class,
        )

    # Step 8: derive obligation from violated condition or specific contract mismatch
    obligation = _derive_obligation(
        predicate=predicate,
        error_line=error_line,
    )

    # Refine obligation with specific reject info (helper contract violations, etc.)
    specific_reject = extract_specific_reject_info(parsed_log)
    if specific_reject is not None:
        obligation = _refine_obligation(obligation, specific_reject)

    # Step 9: build proof events from monitor + transition results
    proof_events = _build_proof_events(
        monitor_result=monitor_result,
        predicate=predicate,
        parsed_trace=parsed_trace,
    )

    # Step 10: correlate events to source spans
    spans = correlate_to_source(
        parsed_trace,
        proof_events,
        bpftool_source_map=bpftool_source_map,
    )
    spans = _ensure_rejected_span(spans, parsed_trace, parsed_log)

    # Step 11: build note and help text
    note = _build_note(
        parsed_log,
        taxonomy_class=taxonomy_class,
        obligation=obligation,
        proof_status=proof_status,
        specific_reject=specific_reject,
    )
    help_text = _build_help_text(
        parsed_log,
        taxonomy_class=taxonomy_class,
        obligation=obligation,
        proof_status=proof_status,
        specific_reject=specific_reject,
    )

    # Step 12: compute backward slice for causal-chain context.
    # Determine the criterion: error instruction + the primary register of interest.
    # Prefer the predicate's target register; fall back to the first register
    # used or defined by the error instruction.
    slice_criterion_insn: int | None = None
    slice_criterion_reg: str | None = None

    if structural_taxonomy_class is None and error_insn is not None:
        slice_criterion_insn = error_insn.insn_idx
        if predicate is not None:
            target_regs = getattr(predicate, "target_regs", [])
            slice_criterion_reg = target_regs[0] if target_regs else None
        if slice_criterion_reg is None:
            from .engine.dataflow import extract_uses, extract_defs
            bytecode = error_insn.bytecode or ""
            uses = extract_uses(bytecode)
            defs = extract_defs(bytecode)
            regs = list(uses) or list(defs)
            slice_criterion_reg = regs[0] if regs else None

    # Build the backward slice (principled data + control dependence).
    # Only run if we have a clear criterion.
    use_slice_chain = (
        slice_criterion_insn is not None
        and slice_criterion_reg is not None
        and len(instructions) > 0
    )

    causal_chain: list[tuple[int, str]]

    if use_slice_chain:
        bslice = backward_slice(
            instructions,
            criterion_insn=slice_criterion_insn,
            criterion_register=slice_criterion_reg,
            cfg=cross_cfg,
        )
        # Build causal chain entries: each instruction in the ordered slice
        # (excluding the criterion itself, which appears as the rejected event).
        causal_chain = []
        indexed = {insn.insn_idx: insn for insn in instructions}
        for insn_idx in bslice.ordered:
            if insn_idx == slice_criterion_insn:
                continue
            insn_obj = indexed.get(insn_idx)
            bytecode_text = insn_obj.bytecode if insn_obj else ""
            # Annotate with "data" or "control" for the reason field.
            if insn_idx in bslice.data_deps:
                reason = f"data_dep: {bytecode_text}"
            else:
                reason = f"control_dep: {bytecode_text}"
            causal_chain.append((insn_idx, reason))
    else:
        causal_chain = [
            (d.insn_idx, d.reason)
            for d in transition_chain.chain
            if d.effect in (TransitionEffect.DESTROYING, TransitionEffect.WIDENING)
        ]

    output = render_diagnostic(
        error_id=parsed_log.error_id or "BPFIX-UNKNOWN",
        taxonomy_class=taxonomy_class,
        proof_status=proof_status,
        spans=spans,
        obligation=obligation,
        note=note,
        help_text=help_text,
        confidence=_confidence_to_float(parsed_log.catalog_confidence),
        diagnosis_evidence=parsed_log.evidence,
        raw_log_excerpt=(specific_reject.raw if specific_reject is not None else parsed_log.error_line) or None,
    )

    metadata = output.json_data.setdefault("metadata", {})
    metadata["cross_analysis_class"] = cross_analysis_class
    if cross_atom_results:
        metadata["active_atoms"] = [
            _atom_classification_to_dict(result)
            for result in cross_atom_results
            if result.classification != "inactive"
        ]

    # Attach causal chain to metadata if present
    if causal_chain:
        metadata["causal_chain"] = [
            {"insn_idx": idx, "reason": reason} for idx, reason in causal_chain
        ]

    # Also attach backward slice metadata when available.
    if use_slice_chain and bslice.full_slice:
        metadata["backward_slice"] = {
            "criterion_insn": slice_criterion_insn,
            "criterion_register": slice_criterion_reg,
            "full_slice": sorted(bslice.full_slice),
            "data_deps": sorted(bslice.data_deps),
            "control_deps": sorted(bslice.control_deps),
        }

    return output


# ---------------------------------------------------------------------------
# Cross-analysis helpers
# ---------------------------------------------------------------------------

def compute_forward_dominators(cfg: TraceCFG | None) -> dict[int, set[int]]:
    """Return a dominance relation as {dominator: dominated_nodes}."""
    if cfg is None:
        return {}

    all_nodes = set(cfg.insn_successors) | set(cfg.insn_predecessors)
    if not all_nodes:
        return {}

    dom: dict[int, set[int]] = {node: set(all_nodes) for node in all_nodes}
    entry = cfg.entry
    dom[entry] = {entry}

    changed = True
    while changed:
        changed = False
        for node in sorted(all_nodes):
            if node == entry:
                continue
            preds = cfg.insn_predecessors.get(node, set()) & all_nodes
            if not preds:
                new_dom = {node}
            else:
                pred_iter = iter(preds)
                new_dom = set(dom.get(next(pred_iter), set(all_nodes)))
                for pred in pred_iter:
                    new_dom &= dom.get(pred, set(all_nodes))
                new_dom.add(node)
            if new_dom != dom.get(node):
                dom[node] = new_dom
                changed = True

    dominates: dict[int, set[int]] = {node: set() for node in all_nodes}
    for node, dominators in dom.items():
        for dominator in dominators:
            dominates.setdefault(dominator, set()).add(node)
    return dominates


def slice_contains_back_edge(bslice, cfg: TraceCFG | None) -> bool:
    if cfg is None or not getattr(bslice, "full_slice", None):
        return False

    slice_nodes = set(bslice.full_slice)
    for src, succs in cfg.insn_successors.items():
        if src not in slice_nodes:
            continue
        for dst in succs:
            if dst in slice_nodes and dst <= src:
                return True
    return False


def classify_atom(
    schema: SafetySchema,
    error_insn: Any,
    traced_insns: list[Any],
    cfg: TraceCFG | None,
    dominators: dict[int, set[int]],
    *,
    primary: CarrierSpec | None = None,
    monitoring: dict[str, CarrierLifecycle] | None = None,
    bslice: Any | None = None,
    reject_evaluation: str | None = None,
) -> AtomClassification:
    if primary is None:
        primary = instantiate_primary_carrier(schema, error_insn)
    if primary is None:
        return AtomClassification(
            classification="ambiguous",
            schema=schema,
            primary=None,
            reason="no_primary_carrier",
            reject_evaluation="unknown",
        )

    if reject_evaluation is None:
        reject_condition = instantiate_schema(schema, primary)
        reject_evaluation = evaluate_condition(reject_condition, error_insn.pre_state)

    if reject_evaluation == "satisfied":
        return AtomClassification(
            classification="inactive",
            schema=schema,
            primary=primary,
            reject_evaluation=reject_evaluation,
        )

    if monitoring is None:
        carriers = discover_compatible_carriers(schema, primary, error_insn.pre_state)
        monitoring = monitor_carriers(schema, carriers, traced_insns)

    if bslice is None:
        bslice = backward_slice(
            traced_insns,
            criterion_insn=error_insn.insn_idx,
            criterion_register=primary.register,
            cfg=cfg,
        )

    if slice_contains_back_edge(bslice, cfg):
        return AtomClassification(
            classification="ambiguous",
            schema=schema,
            primary=primary,
            reason="loop_back_edge",
            reject_evaluation=reject_evaluation,
            lifecycles=monitoring,
            backward_slice=bslice,
        )

    any_establish = False
    any_non_dominating_establish = False
    any_off_chain_establish = False
    vacuous_on_chain_loss: tuple[CarrierLifecycle, LifecycleEvent] | None = None
    vacuous_off_chain_loss: tuple[CarrierLifecycle, LifecycleEvent] | None = None
    full_slice = set(bslice.full_slice)

    for lifecycle in monitoring.values():
        establishes = [event for event in lifecycle.events if event.kind == "establish"]
        losses = [event for event in lifecycle.events if event.kind == "loss"]

        if establishes:
            any_establish = True

        dominating_establishes: list[LifecycleEvent] = []
        for establish in establishes:
            if error_insn.insn_idx in dominators.get(establish.insn_idx, set()):
                dominating_establishes.append(establish)
            else:
                any_non_dominating_establish = True

        dominating_losses = [
            loss
            for loss in losses
            if error_insn.insn_idx in dominators.get(loss.insn_idx, set())
        ]

        if losses and not establishes and lifecycle.first_observed_gap == 0:
            on_chain_vacuous_loss = next(
                (loss for loss in dominating_losses if loss.insn_idx in full_slice),
                None,
            )
            if on_chain_vacuous_loss is not None and vacuous_on_chain_loss is None:
                vacuous_on_chain_loss = (lifecycle, on_chain_vacuous_loss)
            elif dominating_losses and vacuous_off_chain_loss is None:
                vacuous_off_chain_loss = (lifecycle, dominating_losses[0])

        for establish in dominating_establishes:
            if establish.insn_idx not in full_slice:
                any_off_chain_establish = True
                continue

            later_on_chain_loss = next(
                (
                    loss
                    for loss in dominating_losses
                    if loss.trace_pos > establish.trace_pos
                    and loss.insn_idx in full_slice
                ),
                None,
            )
            if later_on_chain_loss is not None:
                return AtomClassification(
                    classification="established_then_lost",
                    schema=schema,
                    primary=primary,
                    carrier=lifecycle.carrier,
                    establish=establish,
                    loss=later_on_chain_loss,
                    reject_evaluation=reject_evaluation,
                    lifecycles=monitoring,
                    backward_slice=bslice,
                )

    if vacuous_on_chain_loss is not None:
        lifecycle, loss = vacuous_on_chain_loss
        return AtomClassification(
            classification="established_then_lost",
            schema=schema,
            primary=primary,
            carrier=lifecycle.carrier,
            reason="vacuous_establishment",
            loss=loss,
            reject_evaluation=reject_evaluation,
            lifecycles=monitoring,
            backward_slice=bslice,
        )

    if vacuous_off_chain_loss is not None:
        lifecycle, loss = vacuous_off_chain_loss
        return AtomClassification(
            classification="lowering_artifact",
            schema=schema,
            primary=primary,
            carrier=lifecycle.carrier,
            reason="vacuous_establishment",
            loss=loss,
            reject_evaluation=reject_evaluation,
            lifecycles=monitoring,
            backward_slice=bslice,
        )

    if any_non_dominating_establish:
        return AtomClassification(
            classification="ambiguous",
            schema=schema,
            primary=primary,
            reason="branch_local_establish",
            reject_evaluation=reject_evaluation,
            lifecycles=monitoring,
            backward_slice=bslice,
        )

    if any_off_chain_establish:
        return AtomClassification(
            classification="lowering_artifact",
            schema=schema,
            primary=primary,
            reject_evaluation=reject_evaluation,
            lifecycles=monitoring,
            backward_slice=bslice,
        )

    if not any_establish:
        return AtomClassification(
            classification="source_bug",
            schema=schema,
            primary=primary,
            reject_evaluation=reject_evaluation,
            lifecycles=monitoring,
            backward_slice=bslice,
        )

    return AtomClassification(
        classification="ambiguous",
        schema=schema,
        primary=primary,
        reason="incomplete_temporal_story",
        reject_evaluation=reject_evaluation,
        lifecycles=monitoring,
        backward_slice=bslice,
    )


def aggregate_atom_classes(atom_classes: list[str]) -> str:
    active = [atom_class for atom_class in atom_classes if atom_class != "inactive"]
    if not active:
        return "ambiguous"
    if "ambiguous" in active:
        return "ambiguous"
    if "source_bug" in active:
        return "source_bug"
    if len(set(active)) == 1:
        return active[0]
    return "ambiguous"


def _atom_classification_to_dict(result: AtomClassification) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "classification": result.classification,
        "reason": result.reason,
        "reject_evaluation": result.reject_evaluation,
        "schema": _schema_to_dict(result.schema),
    }
    if result.primary is not None:
        payload["primary"] = _carrier_to_dict(result.primary)
    if result.carrier is not None:
        payload["carrier"] = _carrier_to_dict(result.carrier)
    if result.establish is not None:
        payload["establish"] = _event_to_dict(result.establish)
    if result.loss is not None:
        payload["loss"] = _event_to_dict(result.loss)
    if result.lifecycles:
        payload["carrier_lifecycles"] = {
            register: _lifecycle_to_dict(lifecycle)
            for register, lifecycle in result.lifecycles.items()
        }
    if result.backward_slice is not None:
        payload["backward_slice"] = {
            "criterion_insn": result.backward_slice.criterion_insn,
            "criterion_register": result.backward_slice.criterion_register,
            "full_slice": sorted(result.backward_slice.full_slice),
            "data_deps": sorted(result.backward_slice.data_deps),
            "control_deps": sorted(result.backward_slice.control_deps),
        }
    return payload


def _schema_to_dict(schema: SafetySchema) -> dict[str, Any]:
    return {
        "domain": schema.domain.value,
        "role": schema.role.value,
        "access_size": schema.access_size,
        "pointer_kind": schema.pointer_kind,
        "expected_types": list(schema.expected_types),
        "allow_null": schema.allow_null,
        "requires_range": schema.requires_range,
        "requires_writable": schema.requires_writable,
        "helper_id": schema.helper_id,
        "helper_name": schema.helper_name,
        "helper_arg_index": schema.helper_arg_index,
        "constraint": schema.constraint,
    }


def _carrier_to_dict(carrier: CarrierSpec) -> dict[str, Any]:
    return {
        "register": carrier.register,
        "role": carrier.role.value,
        "pointer_kind": carrier.pointer_kind,
        "provenance_id": carrier.provenance_id,
        "reject_type": carrier.reject_type,
        "is_primary": carrier.is_primary,
    }


def _event_to_dict(event: LifecycleEvent) -> dict[str, Any]:
    return {
        "kind": event.kind,
        "trace_pos": event.trace_pos,
        "insn_idx": event.insn_idx,
        "gap_before": event.gap_before,
        "gap_after": event.gap_after,
        "reason": event.reason,
    }


def _lifecycle_to_dict(lifecycle: CarrierLifecycle) -> dict[str, Any]:
    return {
        "carrier": (
            _carrier_to_dict(lifecycle.carrier)
            if lifecycle.carrier is not None
            else None
        ),
        "events": [_event_to_dict(event) for event in lifecycle.events],
        "establish_site": lifecycle.establish_site,
        "loss_site": lifecycle.loss_site,
        "final_gap": lifecycle.final_gap,
        "first_observed_gap": lifecycle.first_observed_gap,
        "proof_status": lifecycle.proof_status,
    }


# ---------------------------------------------------------------------------
# Step 7: derive proof status from engine results
# ---------------------------------------------------------------------------

def _derive_proof_status(
    *,
    monitor_result: Any,
    transition_chain: Any,
    predicate: Any,
    error_insn: Any,
) -> str:
    """Derive proof_status from engine results only."""
    has_error_insn = error_insn is not None

    if predicate is not None:
        status = monitor_result.proof_status
        if (
            status == "established_but_insufficient"
            and transition_chain.proof_status == "established_then_lost"
            and transition_chain.establish_point is not None
            and transition_chain.loss_point is not None
        ):
            return "established_then_lost"
        return status

    if (
        has_error_insn
        and transition_chain.proof_status == "established_then_lost"
        and transition_chain.establish_point is not None
        and transition_chain.loss_point is not None
    ):
        return "established_then_lost"

    if has_error_insn:
        return "never_established"

    return "unknown"


def _derive_taxonomy_class(
    *,
    predicate: Any,
    proof_status: str,
    monitor_result: Any,
    error_insn: Any,
    parsed_log: ParsedLog,
) -> str:
    """Derive taxonomy from the principled engine path when available.

    Structural cases without an instruction-level safety condition fall back to
    the cataloged error ID, which is kept only for meta-errors outside the
    opcode/predicate path.
    """
    if predicate is not None or error_insn is not None:
        if proof_status == "established_then_lost" or monitor_result.loss_site is not None:
            return "lowering_artifact"
        return "source_bug"

    error_id = parsed_log.error_id
    if error_id is not None:
        taxonomy = _STRUCTURAL_TAXONOMY_BY_ERROR_ID.get(error_id)
        if taxonomy is not None:
            return taxonomy

    return "source_bug"


def _override_taxonomy_class(
    fallback_taxonomy: str,
    cross_analysis_class: str | None,
) -> str:
    if cross_analysis_class is None:
        return fallback_taxonomy
    if cross_analysis_class in {"established_then_lost", "lowering_artifact"}:
        return "lowering_artifact"
    if cross_analysis_class == "source_bug":
        return "source_bug"
    if cross_analysis_class == "ambiguous":
        return fallback_taxonomy
    return fallback_taxonomy


# ---------------------------------------------------------------------------
# Step 8: derive obligation
# ---------------------------------------------------------------------------

def _derive_obligation(
    *,
    predicate: Any,
    error_line: str,
) -> ProofObligation | None:
    """Derive proof obligation from violated safety condition or error line."""
    if predicate is not None:
        target_regs = getattr(predicate, "target_regs", [])
        base_reg = target_regs[0] if target_regs else "R0"
        required = _predicate_required_condition(predicate) or error_line
        return ProofObligation(
            obligation_type=_predicate_to_obligation_type(predicate),
            register=base_reg,
            required_condition=required,
            description=f"Inferred from: {error_line}",
        )

    # No predicate: check for specific contract mismatch in error line
    specific_contract = extract_specific_contract_mismatch(error_line)
    if specific_contract is not None:
        return ProofObligation(
            obligation_type="helper_arg",
            register="R0",
            required_condition=specific_contract.raw,
            description=specific_contract.raw,
        )

    return None


def _refine_obligation(
    obligation: ProofObligation | None,
    specific_reject: SpecificRejectInfo,
) -> ProofObligation | None:
    """Refine or replace obligation with info from specific reject (helper contracts, etc.)."""
    specific_required = getattr(specific_reject, "obligation_required", None)
    specific_type = getattr(specific_reject, "obligation_type", None)

    if specific_required and specific_type:
        if obligation is None:
            return ProofObligation(
                obligation_type=specific_type,
                register="R1",
                required_condition=specific_required,
                description=f"Contract violation: {specific_required}",
            )
        # Refine existing obligation with more specific info
        current_required = getattr(obligation, "required_condition", None) or ""
        if specific_required and specific_required != current_required:
            return ProofObligation(
                obligation_type=specific_type,
                register=getattr(obligation, "register", "R0"),
                required_condition=specific_required,
                description=getattr(obligation, "description", specific_required),
                catalog_id=getattr(obligation, "catalog_id", None),
            )

    return obligation


# ---------------------------------------------------------------------------
# Step 9: build proof events
# ---------------------------------------------------------------------------

def _build_proof_events(
    *,
    monitor_result: Any,
    predicate: Any,
    parsed_trace: ParsedTrace,
) -> list[ProofEvent]:
    """Build proof events from monitor and/or transition_chain results."""
    instructions = list(getattr(parsed_trace, "instructions", []))
    indexed = {insn.insn_idx: insn for insn in instructions}

    target_regs = getattr(predicate, "target_regs", []) if predicate is not None else []
    primary_reg = target_regs[0] if target_regs else "R0"

    events: list[ProofEvent] = []

    if predicate is not None and monitor_result.proof_status not in {"unknown"}:
        # Real SafetyCondition exists: use monitor result for establish/loss sites.
        # The monitor found a real predicate satisfaction/violation, so lifecycle spans are meaningful.
        events = _monitor_result_to_events(monitor_result, indexed, primary_reg)
    # No predicate (structural errors, or opcode_safety returned None):
    # Do NOT produce proof_established/proof_lost spans from TA fallback.
    # TA transition chain is already attached as causal_chain metadata (see step 12).

    # Always add the rejected event if not already present
    if not any(e.event_type == "rejected" for e in events):
        error_insn = next((i for i in instructions if i.is_error), None)
        if error_insn is not None:
            events.append(ProofEvent(
                insn_idx=error_insn.insn_idx,
                event_type="rejected",
                register=primary_reg,
                state_before=error_insn.pre_state.get(primary_reg),
                state_after=error_insn.post_state.get(primary_reg),
                source_line=error_insn.source_line,
                description=error_insn.error_text or "verifier rejected",
            ))

    return events


def _monitor_result_to_events(
    monitor_result: Any,
    indexed: dict[int, Any],
    primary_reg: str,
) -> list[ProofEvent]:
    """Convert MonitorResult to ProofEvent list.

    Temporal ordering is enforced: establish <= loss <= rejected.
    If loss_site > error_insn (verifier backtracking artifact), loss is capped at error_insn.
    """
    events: list[ProofEvent] = []
    error_insn_idx = monitor_result.error_insn

    if monitor_result.establish_site is not None:
        insn = indexed.get(monitor_result.establish_site)
        events.append(ProofEvent(
            insn_idx=monitor_result.establish_site,
            event_type="proof_established",
            register=primary_reg,
            state_before=insn.pre_state.get(primary_reg) if insn else None,
            state_after=insn.post_state.get(primary_reg) if insn else None,
            source_line=insn.source_line if insn else None,
            description=f"Proof obligation satisfied at insn {monitor_result.establish_site}",
        ))

    if monitor_result.loss_site is not None:
        # Cap loss_site at error_insn to preserve temporal ordering
        loss_idx = monitor_result.loss_site
        if error_insn_idx is not None and loss_idx > error_insn_idx:
            loss_idx = error_insn_idx
        insn = indexed.get(loss_idx)
        reason = monitor_result.loss_reason or "proof property violated"
        events.append(ProofEvent(
            insn_idx=loss_idx,
            event_type="proof_lost",
            register=primary_reg,
            state_before=insn.pre_state.get(primary_reg) if insn else None,
            state_after=insn.post_state.get(primary_reg) if insn else None,
            source_line=insn.source_line if insn else None,
            description=reason,
        ))

    if error_insn_idx is not None:
        insn = indexed.get(error_insn_idx)
        events.append(ProofEvent(
            insn_idx=error_insn_idx,
            event_type="rejected",
            register=primary_reg,
            state_before=insn.pre_state.get(primary_reg) if insn else None,
            state_after=insn.post_state.get(primary_reg) if insn else None,
            source_line=insn.source_line if insn else None,
            description=(insn.error_text if insn else None) or "verifier rejected",
        ))

    return events

# ---------------------------------------------------------------------------
# Step 10: ensure there's always a rejected span
# ---------------------------------------------------------------------------

def _ensure_rejected_span(
    spans: list[SourceSpan],
    parsed_trace: ParsedTrace,
    parsed_log: ParsedLog,
) -> list[SourceSpan]:
    """Ensure there is at least one rejected span in the output."""
    if any(s.role == "rejected" for s in spans):
        return spans

    instructions = list(getattr(parsed_trace, "instructions", []))

    # Try error instruction first
    for insn in reversed(instructions):
        if insn.is_error:
            return list(spans) + [SourceSpan(
                file=None,
                line=None,
                source_text=insn.bytecode,
                insn_range=(insn.insn_idx, insn.insn_idx),
                role="rejected",
                register=None,
                state_change=None,
                reason=insn.error_text or "verifier rejected",
            )]

    # Last instruction as fallback
    if instructions:
        last_insn = instructions[-1]
        from .source_correlator import _extract_source_fields
        source_text, file_name, line_number = _extract_source_fields(
            last_insn.source_line, last_insn.bytecode
        )
        return list(spans) + [SourceSpan(
            file=file_name,
            line=line_number,
            source_text=source_text,
            insn_range=(last_insn.insn_idx, last_insn.insn_idx),
            role="rejected",
            register=None,
            state_change=None,
            reason=parsed_log.error_line or "verifier rejected",
        )]

    # Error line only
    if parsed_log.error_line:
        return list(spans) + [SourceSpan(
            file=None,
            line=None,
            source_text=parsed_log.error_line,
            insn_range=(0, 0),
            role="rejected",
            register=None,
            state_change=None,
            reason=parsed_log.error_line,
        )]

    return spans


# ---------------------------------------------------------------------------
# Step 11: note and help text
# ---------------------------------------------------------------------------

def _build_note(
    parsed_log: ParsedLog,
    *,
    taxonomy_class: str,
    obligation: ProofObligation | None,
    proof_status: str,
    specific_reject: SpecificRejectInfo | None,
) -> str | None:
    if specific_reject is not None and specific_reject.note:
        return specific_reject.note

    if taxonomy_class == "lowering_artifact" and proof_status == "established_then_lost":
        return "A verifier-visible proof existed earlier but was lost before the rejected instruction."

    if parsed_log.error_id == "BPFIX-E002":
        return "The dereference happens while the pointer is still nullable on this control-flow path."

    specific_contract = extract_specific_contract_mismatch(parsed_log.error_line)
    if taxonomy_class == "source_bug" and specific_contract is not None and proof_status in {"never_established", "unknown"}:
        return specific_contract_note(specific_contract)

    if obligation is not None and proof_status == "never_established":
        obl_type = getattr(obligation, "obligation_type", "unknown")
        return f"The required {obl_type.replace('_', ' ')} proof was never established."

    for line in (parsed_log.evidence or []):
        if line.startswith("Proof existed earlier") or line.startswith("No earlier"):
            return line

    return None


def _build_help_text(
    parsed_log: ParsedLog,
    *,
    taxonomy_class: str,
    obligation: ProofObligation | None,
    proof_status: str,
    specific_reject: SpecificRejectInfo | None,
) -> str | None:
    if specific_reject is not None and specific_reject.help_text:
        return specific_reject.help_text

    specific_contract = extract_specific_contract_mismatch(parsed_log.error_line)
    obl_type = getattr(obligation, "obligation_type", None) if obligation else None

    if (
        taxonomy_class == "source_bug"
        and specific_contract is not None
        and (
            proof_status == "never_established"
            or obl_type == "helper_arg"
            or parsed_log.error_id == "BPFIX-E023"
        )
    ):
        specific_help = specific_contract_help(parsed_log, specific_contract)
        if specific_help is not None:
            return specific_help

    catalog_path = Path(__file__).resolve().parents[1] / "catalogs" / "obligation_catalog.yaml"
    templates = _load_obligation_templates(str(catalog_path.resolve()))

    error_id = parsed_log.error_id
    for template in templates.get("templates", []):
        if error_id and error_id in template.get("related_error_ids", []):
            hints = template.get("repair_hints") or []
            if hints:
                return hints[0]

    return None


@lru_cache(maxsize=None)
def _load_obligation_templates(catalog_path: str) -> dict[str, Any]:
    try:
        return yaml.safe_load(Path(catalog_path).read_text(encoding="utf-8")) or {}
    except OSError:
        return {}


# ---------------------------------------------------------------------------
# Helpers: predicate introspection
# ---------------------------------------------------------------------------

def _predicate_required_condition(
    predicate: Any,
) -> str | None:
    """Extract the required condition string from a predicate."""
    from .engine.opcode_safety import OpcodeConditionPredicate as _OCP
    if isinstance(predicate, _OCP):
        cond = predicate.condition
        target_regs = getattr(predicate, "target_regs", [])
        parts = [f"{r}: {cond.required_property}" for r in target_regs]
        return "; ".join(parts) if parts else None
    return None


def _predicate_to_obligation_type(predicate: Any) -> str:
    """Map a Predicate instance to a semantic obligation type string."""
    from .engine.opcode_safety import OpcodeConditionPredicate as _OCP, SafetyDomain
    if isinstance(predicate, _OCP):
        mapping = {
            SafetyDomain.MEMORY_BOUNDS: "bounds_check",
            SafetyDomain.POINTER_TYPE: "type_check",
            SafetyDomain.SCALAR_BOUND: "scalar_bound",
            SafetyDomain.NULL_SAFETY: "null_check",
            SafetyDomain.REFERENCE_BALANCE: "ref_balance",
            SafetyDomain.ARG_CONTRACT: "helper_arg",
            SafetyDomain.WRITE_PERMISSION: "write_permission",
            SafetyDomain.ARITHMETIC_LEGALITY: "arith_legality",
        }
        return mapping.get(predicate.condition.domain, "safety_violation")
    return type(predicate).__name__.lower()


def _confidence_to_float(confidence: str | float | None) -> float | None:
    if confidence is None:
        return None
    if isinstance(confidence, float):
        return confidence
    mapping = {"high": 0.9, "medium": 0.6, "low": 0.3, "very_low": 0.1}
    return mapping.get(str(confidence).lower().strip())
