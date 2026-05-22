"""Render correlated proof spans as Rust-style text and structured JSON."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .source_correlator import ProofObligation, SourceSpan

DIAGNOSTIC_VERSION = "0.1.0"
VALID_FAILURE_CLASSES = {
    "source_bug",
    "lowering_artifact",
    "verifier_limit",
    "environment_or_configuration",
    "verifier_false_positive",
}


@dataclass(slots=True)
class DiagnosticOutput:
    text: str
    json_data: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        """Preserve the pre-refactor dict-like access pattern for JSON callers."""
        return self.json_data.get(key, default)


def render_diagnostic(
    error_id: str,
    taxonomy_class: str,
    proof_status: str,
    spans: list[SourceSpan],
    obligation: ProofObligation | None,
    note: str | None,
    help_text: str | None,
    *,
    confidence: float | None = None,
    diagnosis_evidence: list[str] | None = None,
    raw_log_excerpt: str | None = None,
) -> DiagnosticOutput:
    """Render a proof-aware diagnostic in text and JSON forms."""

    ordered_spans = sorted(spans, key=lambda span: (span.insn_range[0], span.insn_range[1]))
    headline = _headline_summary(taxonomy_class, proof_status, obligation)
    text_lines = [f"error[{error_id}]: {taxonomy_class} — {headline}"]

    if ordered_spans:
        header = _header_label(ordered_spans)
        width = max(len(str(_display_line(span))) for span in ordered_spans)
        text_lines.extend(
            [
                f"  ┌─ {header}",
                "  │",
            ]
        )
        for span in ordered_spans:
            line_label = str(_display_line(span)).rjust(width)
            text_lines.append(f"{line_label} │     {span.source_text}")
            text_lines.append(
                f"{' ' * width} │     {_underline(span.source_text)} {_role_label(span)}"
            )
            if span.state_change:
                text_lines.append(
                    f"{' ' * width} │     {_display_state_change(span.state_change)}"
                )
            text_lines.append(f"{' ' * width} │")
    else:
        text_lines.append("  = note: no source-correlated spans available")

    if note:
        text_lines.append(f"  = note: {note}")
    if help_text:
        text_lines.append(f"  = help: {help_text}")

    normalized_failure_class = _normalize_failure_class(taxonomy_class, proof_status)
    primary_span = _select_primary_span(ordered_spans)
    verifier_span = _select_last_span_with_role(ordered_spans, "rejected") or primary_span
    evidence = _build_evidence_items(
        ordered_spans,
        diagnosis_evidence=diagnosis_evidence or [],
        note=note,
        raw_log_excerpt=raw_log_excerpt,
    )
    metadata = _build_metadata(
        ordered_spans,
        taxonomy_class=taxonomy_class,
        proof_status=proof_status,
        obligation=obligation,
        note=note,
        help_text=help_text,
        normalized_failure_class=normalized_failure_class,
    )

    json_data: dict[str, Any] = {
        "diagnostic_version": DIAGNOSTIC_VERSION,
        "error_id": error_id,
        "failure_class": normalized_failure_class,
        "message": headline,
        "source_span": _render_source_span(primary_span),
        "missing_obligation": _missing_obligation_text(obligation),
        "evidence": evidence,
        "candidate_repairs": _build_candidate_repairs(
            normalized_failure_class,
            obligation=obligation,
            note=note,
            help_text=help_text,
        ),
    }

    verifier_site = _render_verifier_site(verifier_span)
    if verifier_site is not None:
        json_data["verifier_site"] = verifier_site

    expected_state = _build_expected_state(ordered_spans, obligation)
    if expected_state is not None:
        json_data["expected_state"] = expected_state

    observed_state = _build_observed_state(
        ordered_spans,
        note=note,
        raw_log_excerpt=raw_log_excerpt,
    )
    if observed_state is not None:
        json_data["observed_state"] = observed_state

    if confidence is not None:
        json_data["confidence"] = max(0.0, min(1.0, confidence))

    if raw_log_excerpt:
        json_data["raw_log_excerpt"] = raw_log_excerpt

    if metadata:
        json_data["metadata"] = metadata

    return DiagnosticOutput(text="\n".join(text_lines), json_data=json_data)


def _headline_summary(
    taxonomy_class: str,
    proof_status: str,
    obligation: ProofObligation | None,
) -> str:
    if taxonomy_class == "lowering_artifact" and proof_status == "established_then_lost":
        if obligation and _obligation_type(obligation) == "packet_access":
            return "packet access with lost proof"
        return "proof established, then lost before rejection"
    if taxonomy_class == "source_bug" and obligation and _obligation_type(obligation) == "helper_arg":
        helper_headline = _helper_contract_headline(_obligation_required(obligation))
        if helper_headline is not None:
            return helper_headline
    if taxonomy_class == "source_bug" and proof_status == "never_established":
        if obligation and _obligation_type(obligation) == "non_null_dereference":
            return "nullable pointer dereferenced without refinement"
        return "required proof never established"
    if proof_status == "established_but_insufficient":
        return "proof exists but is insufficient at the reject site"
    if proof_status == "unknown":
        return "verifier rejection"
    return proof_status.replace("_", " ")


def _header_label(spans: list[SourceSpan]) -> str:
    file_names = [span.file for span in spans if span.file]
    if file_names:
        return file_names[0]
    if any(_looks_like_source(span.source_text) for span in spans):
        return "<source>"
    return "<bytecode>"


def _looks_like_source(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith("r") and " " in stripped and "+=" in stripped:
        return False
    return any(token in stripped for token in (";", "{", "}", "->", "__", "if (", "for("))


def _display_line(span: SourceSpan) -> int:
    if span.line is not None:
        return span.line
    return span.insn_range[0]


def _underline(source_text: str) -> str:
    visible = source_text.lstrip()
    return "─" * max(6, min(len(visible), 36))


def _role_label(span: SourceSpan) -> str:
    labels = {
        "proof_established": "proof established",
        "proof_propagated": "proof propagated",
        "proof_lost": "proof lost",
        "rejected": "rejected",
    }
    label = labels.get(span.role, span.role.replace("_", " "))
    if span.role == "proof_lost" and span.reason:
        return f"{label}: {span.reason}"
    return label


def _display_state_change(state_change: str) -> str:
    return state_change.replace(" -> ", " → ")


def _normalize_failure_class(taxonomy_class: str, proof_status: str) -> str:
    # Use the taxonomy classification from log_parser as the authoritative source.
    # The proof_status is diagnostic metadata only — it does NOT override taxonomy.
    # (Previously this unconditionally mapped established_then_lost → lowering_artifact,
    # which caused false positives when TransitionAnalyzer falsely reported lifecycle.)
    if taxonomy_class in VALID_FAILURE_CLASSES:
        return taxonomy_class
    return "source_bug"


def _select_primary_span(spans: list[SourceSpan]) -> SourceSpan | None:
    for role in ("rejected", "proof_lost", "proof_established", "proof_propagated"):
        span = _select_last_span_with_role(spans, role)
        if span is not None:
            return span
    return spans[-1] if spans else None


def _select_last_span_with_role(spans: list[SourceSpan], role: str) -> SourceSpan | None:
    for span in reversed(spans):
        if span.role == role:
            return span
    return None


def _render_source_span(span: SourceSpan | None) -> dict[str, Any]:
    payload = {
        "path": _span_path(span),
        "line_start": _span_line_start(span),
        "line_end": _span_line_end(span),
    }
    if span is not None and span.source_text:
        payload["snippet"] = span.source_text
    return payload


def _render_verifier_site(span: SourceSpan | None) -> dict[str, Any] | None:
    if span is None:
        return None
    return {"instruction_index": span.insn_range[0]}


def _build_expected_state(
    spans: list[SourceSpan],
    obligation: ProofObligation | None,
) -> dict[str, Any] | None:
    registers = _collect_register_states(
        spans,
        roles={"proof_established", "proof_propagated"},
        prefer_after=True,
    )
    notes: list[str] = []
    obligation_type = _obligation_type(obligation) if obligation is not None else "unknown"
    if obligation_type != "unknown":
        notes.append(f"Expected proof: {obligation_type.replace('_', ' ')}")
    if obligation is not None:
        notes.append(_obligation_required(obligation))
    return _render_abstract_state(registers, _unique_strings(notes))


def _build_observed_state(
    spans: list[SourceSpan],
    *,
    note: str | None,
    raw_log_excerpt: str | None,
) -> dict[str, Any] | None:
    registers = _collect_register_states(
        spans,
        roles={"proof_lost", "rejected"},
        prefer_after=True,
    )
    notes = [span.reason for span in spans if span.reason]
    if note:
        notes.append(note)
    if raw_log_excerpt:
        notes.append(raw_log_excerpt)
    return _render_abstract_state(registers, _unique_strings(notes))


def _collect_register_states(
    spans: list[SourceSpan],
    *,
    roles: set[str],
    prefer_after: bool,
) -> dict[str, str]:
    registers: dict[str, str] = {}
    for span in spans:
        if span.role not in roles:
            continue
        state = _structured_state_value(span, prefer_after=prefer_after)
        if state is None or span.register is None:
            continue
        registers[span.register] = state
    return registers


def _structured_state_value(
    span: SourceSpan,
    *,
    prefer_after: bool,
) -> str | None:
    if prefer_after and span.state_after is not None:
        return span.state_after
    if span.state_before is not None:
        return span.state_before
    if span.state_after is not None:
        return span.state_after
    if span.state_change is None:
        return None
    parsed = _parse_state_change(span.state_change)
    if parsed is None:
        return None
    _register, before, after = parsed
    return after if prefer_after and after is not None else before


def _render_abstract_state(
    registers: dict[str, str],
    notes: list[str],
) -> dict[str, Any] | None:
    state: dict[str, Any] = {}
    if registers:
        state["registers"] = registers
    if notes:
        state["notes"] = notes
    return state or None


def _parse_state_change(state_change: str) -> tuple[str, str, str | None] | None:
    if ": " not in state_change:
        return None
    register, payload = state_change.split(": ", 1)
    register = register.strip()
    if not register:
        return None
    for separator in (" → ", " -> "):
        if separator in payload:
            before, after = payload.split(separator, 1)
            return register, before.strip(), after.strip()
    return register, payload.strip(), None


def _build_evidence_items(
    spans: list[SourceSpan],
    *,
    diagnosis_evidence: list[str],
    note: str | None,
    raw_log_excerpt: str | None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    if raw_log_excerpt:
        items.append({"kind": "verifier_log", "detail": raw_log_excerpt})

    for span in spans:
        items.append(
            {
                "kind": "source_map",
                "detail": _span_evidence_detail(span),
                "instruction_index": span.insn_range[0],
            }
        )
        if span.state_change:
            items.append(
                {
                    "kind": "abstract_state",
                    "detail": _display_state_change(span.state_change),
                    "instruction_index": span.insn_range[0],
                }
            )
        if span.reason:
            items.append(
                {
                    "kind": "heuristic",
                    "detail": span.reason,
                    "instruction_index": span.insn_range[0],
                }
            )

    if note:
        items.append({"kind": "heuristic", "detail": note})

    for detail in diagnosis_evidence:
        items.append(
            {
                "kind": _evidence_kind_for_detail(detail),
                "detail": detail,
            }
        )

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    for item in items:
        key = (
            str(item["kind"]),
            str(item["detail"]),
            item.get("instruction_index"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[:12]


def _span_evidence_detail(span: SourceSpan) -> str:
    location = f"{_span_path(span)}:{_span_line_start(span)}"
    return f"{span.role.replace('_', ' ')} at {location}: {span.source_text}"


def _evidence_kind_for_detail(detail: str) -> str:
    lowered = detail.lower()
    if any(token in lowered for token in ("kernel", "btf", "helper", "kfunc", "attach")):
        return "kernel_capability"
    return "heuristic"


def _build_candidate_repairs(
    failure_class: str,
    *,
    obligation: ProofObligation | None,
    note: str | None,
    help_text: str | None,
) -> list[dict[str, Any]]:
    if not help_text:
        return []

    action = _repair_action_for(failure_class, obligation, help_text)
    rationale = note or _repair_rationale(failure_class, obligation, help_text)
    repair = {
        "action": action,
        "rationale": rationale,
        "patch_hint": help_text,
    }
    return [repair]


def _repair_action_for(
    failure_class: str,
    obligation: ProofObligation | None,
    help_text: str,
) -> str:
    hint = help_text.lower()
    obligation_type = _obligation_type(obligation)

    if failure_class == "source_bug":
        if obligation_type in {"non_null_dereference", "null_check"} or "null check" in hint:
            return "ADD_NULL_CHECK"
        if obligation_type == "packet_access" or "bounds check" in hint or "data_end" in hint:
            return "ADD_BOUNDS_GUARD"
        if any(token in hint for token in ("tighten", "narrow", "offset", "range")):
            return "TIGHTEN_RANGE"
        return "UNKNOWN"

    if failure_class == "lowering_artifact":
        if any(token in hint for token in ("clamp", "mask", "unsigned", "range")):
            return "TIGHTEN_RANGE"
        return "REWRITE_POINTER_ARITH"

    if failure_class == "verifier_limit":
        return "SIMPLIFY_CFG"

    if failure_class == "environment_or_configuration":
        return "GATE_BY_KERNEL_CAPABILITY"

    if failure_class == "verifier_false_positive":
        return "INVESTIGATE_VERIFIER_FALSE_POSITIVE"

    return "UNKNOWN"


def _repair_rationale(
    failure_class: str,
    obligation: ProofObligation | None,
    help_text: str,
) -> str:
    if obligation is not None:
        return f"{failure_class.replace('_', ' ')} blocks the required {_obligation_type(obligation).replace('_', ' ')} proof."
    return help_text


def _build_metadata(
    spans: list[SourceSpan],
    *,
    taxonomy_class: str,
    proof_status: str,
    obligation: ProofObligation | None,
    note: str | None,
    help_text: str | None,
    normalized_failure_class: str,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "proof_status": proof_status,
        "proof_spans": [
            {
                "role": span.role,
                "path": span.file,
                "line": span.line,
                "source_text": span.source_text,
                "insn_range": [span.insn_range[0], span.insn_range[1]],
                "register": span.register,
                "state_change": _display_state_change(span.state_change)
                if span.state_change
                else None,
                "reason": span.reason,
            }
            for span in spans
        ],
    }
    if taxonomy_class not in VALID_FAILURE_CLASSES:
        metadata["reported_failure_class"] = taxonomy_class
    if note:
        metadata["note"] = note
    if help_text:
        metadata["help"] = help_text
    if obligation is not None:
        metadata["obligation"] = {
            "type": _obligation_type(obligation),
            "required": _obligation_required(obligation),
        }
    if normalized_failure_class != taxonomy_class:
        metadata["normalized_failure_class"] = normalized_failure_class
    return metadata


def _missing_obligation_text(obligation: ProofObligation | None) -> str:
    if obligation is None:
        return "manual analysis required to identify the missing proof obligation"
    required = _obligation_required(obligation).strip()
    if required:
        return required
    obligation_type = _obligation_type(obligation)
    return obligation_type.replace("_", " ")


def _span_path(span: SourceSpan | None) -> str:
    if span is None:
        return "<unknown>"
    if span.file:
        return span.file
    if _looks_like_source(span.source_text):
        return "<source>"
    return "<bytecode>"


def _span_line_start(span: SourceSpan | None) -> int:
    if span is None:
        return 1
    if span.line is not None:
        return span.line
    return max(1, span.insn_range[0] + 1)


def _span_line_end(span: SourceSpan | None) -> int:
    if span is None:
        return 1
    if span.line is not None:
        return span.line
    return max(1, span.insn_range[1] + 1)


def _unique_strings(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _obligation_type(obligation: ProofObligation) -> str:
    return getattr(obligation, "type", None) or getattr(obligation, "obligation_type", "unknown")


def _obligation_required(obligation: ProofObligation) -> str:
    return getattr(obligation, "required", None) or getattr(
        obligation,
        "required_condition",
        "",
    )


def _helper_contract_headline(required: str) -> str | None:
    lowered = required.lower()
    if "expected=fp" in lowered or "matches fp" in lowered or "pointer to stack" in lowered:
        return "helper expected a stack pointer"
    if "expected=map_ptr" in lowered or "matches map_ptr" in lowered:
        return "helper expected a map pointer"
    if "must point to scalar" in lowered:
        return "kfunc expected a scalar-compatible pointee"
    if "trusted" in lowered:
        return "call expected a trusted pointer"
    if "expected=" in lowered or "must point to" in lowered or "arg#" in lowered:
        return "helper argument contract mismatch"
    return None
