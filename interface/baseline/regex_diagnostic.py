"""Regex-only baseline diagnostic for verifier logs."""

from __future__ import annotations

from dataclasses import dataclass
import re

from interface.extractor.renderer import DIAGNOSTIC_VERSION, DiagnosticOutput

from .error_patterns import (
    DiagnosticContext,
    ErrorPattern,
    MatchedPattern,
    extract_diagnostic_context,
)
from .taxonomy_rules import classify_failure_class

UNKNOWN_ERROR_ID = "BPFIX-UNKNOWN"
BASELINE_NOTE = "Regex baseline inspected only verifier tail messages and nearby source annotations."
TYPE_EXPECTED_RE = re.compile(r"(R\d+)\s+type=([^ ]+)\s+expected=(.+)", flags=re.IGNORECASE)
INVALID_BPF_CONTEXT_RE = re.compile(
    r"invalid bpf_context access(?: off=(?P<off>-?\d+) size=(?P<size>\d+))?",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True)
class DiagnosticDetails:
    summary: str
    explanation: str
    suggestion: str


def _packet_bounds_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Packet pointer escapes the bounds proven against data_end",
        explanation=(
            "The final access is not dominated by a packet bound that proves both the offset "
            "and access width remain within the packet window."
        ),
        suggestion=(
            "Recompute the packet pointer from the checked base immediately before the "
            "dereference and guard `ptr + size <= data_end` on the same path."
        ),
    )


def _nullable_pointer_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Nullable pointer may be dereferenced before a dominating null check",
        explanation=(
            "The register still carries a nullable verifier type at the reject site, so the "
            "verifier cannot assume the value is non-NULL."
        ),
        suggestion=(
            "Split control flow on `if (!ptr) return ...;` and only dereference the refined "
            "non-null branch."
        ),
    )


def _stack_read_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Stack slot is read before the verifier has seen it initialized",
        explanation=(
            "At least one byte in the accessed stack range is unreadable on the current path "
            "because the verifier has not seen a dominating write to that slot."
        ),
        suggestion=(
            "Initialize the full stack slot on every path before reading it or passing it to a helper."
        ),
    )


def _reference_lifetime_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Reference-acquired object is not released on every path",
        explanation=(
            "The verifier still tracks a live reference at program exit or sees a release "
            "discipline mismatch across control-flow paths."
        ),
        suggestion=(
            "Balance acquire and release operations and ensure the release executes on all exits."
        ),
    )


def _scalar_range_details(error_line: str) -> DiagnosticDetails:
    lowered = error_line.lower()
    if "min value is negative" in lowered:
        summary = "Signed range still allows negative offsets"
    elif "array range" in lowered:
        summary = "Scalar range is too wide for the target array access"
    elif "memory, len pair leads to invalid memory access" in lowered:
        summary = "Pointer or length scalar is not tightly bounded for this helper call"
    else:
        summary = "Scalar range is too wide to prove the final access safe"
    return DiagnosticDetails(
        summary=summary,
        explanation=(
            "A scalar used in pointer arithmetic, indexing, or a pointer/length pair lost a "
            "tight verifier range, so the access can no longer be proven safe from the error line alone."
        ),
        suggestion=(
            "Clamp, mask, or cast the scalar to a small unsigned range before the pointer "
            "arithmetic or helper call that consumes it."
        ),
    )


def _provenance_loss_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Pointer provenance is lost before the dereference or helper use",
        explanation=(
            "The register is no longer treated as the original tracked pointer after spill, "
            "reload, or helper-side transformations."
        ),
        suggestion=(
            "Re-derive the pointer from a verified base after spills, reloads, or helper calls "
            "instead of carrying the transformed value across the boundary."
        ),
    )


def _verifier_limit_details(error_line: str) -> DiagnosticDetails:
    lowered = error_line.lower()
    if lowered.startswith("stack depth"):
        summary = "Stack usage exceeds the verifier's bounded analysis budget"
    elif lowered.startswith("processed"):
        summary = "Verifier reaches its analysis budget before the program can be proven"
    elif "loop is not bounded" in lowered or "back-edge" in lowered:
        summary = "Loop bound or monotonic progress is not proven"
    else:
        summary = "Verifier rejects the program due to bounded analysis limits"
    return DiagnosticDetails(
        summary=summary,
        explanation=(
            "The rejection is driven by verifier resource limits or proof-shape complexity "
            "rather than a single concrete memory-safety violation."
        ),
        suggestion=(
            "Simplify the control flow, split large routines into smaller helpers or subprograms, "
            "and make loop bounds explicit and small."
        ),
    )


def _helper_unavailable_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Helper, kfunc, or attach target is unavailable in this environment",
        explanation=(
            "The requested helper-like capability is not available for the current kernel, "
            "program type, or attach target."
        ),
        suggestion=(
            "Switch to a helper or kfunc supported by this hook, or gate the feature on the "
            "detected kernel capability."
        ),
    )


def _verifier_false_positive_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Verifier appears to reject a safe program conservatively or incorrectly",
        explanation=(
            "The log indicates a verifier-side false positive or internal verifier failure "
            "rather than a stable program-side contract violation."
        ),
        suggestion=(
            "Minimize the reproducer, test across nearby kernel versions, and record whether "
            "the evidence is a precision false positive or an upstream-confirmed verifier bug."
        ),
    )


def _scalar_pointer_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="A scalar is being used where a tracked pointer is required",
        explanation=(
            "The reject-site register is no longer a verifier-tracked pointer, so the final "
            "dereference or helper argument cannot be justified."
        ),
        suggestion=(
            "Keep the base pointer and scalar offset separate, then reload or reconstruct the "
            "pointer from a verified base immediately before use."
        ),
    )


def _dynptr_protocol_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Dynptr API protocol is violated",
        explanation=(
            "The dynptr is not initialized, typed, or consumed in the exact state required by the helper."
        ),
        suggestion=(
            "Initialize the dynptr exactly as required by the API and avoid overwriting or "
            "offsetting the dynptr object before the helper call."
        ),
    )


def _discipline_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Lock, IRQ, RCU, or exception-callback discipline is violated on this path",
        explanation=(
            "The current control-flow path performs an operation that is forbidden while a lock, "
            "IRQ state, RCU requirement, or callback discipline is active."
        ),
        suggestion=(
            "Move the disallowed call out of the protected region and balance the relevant "
            "lock, IRQ, or RCU scope on every exit path."
        ),
    )


def _iterator_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Iterator state is not initialized or not kept on stack as required",
        explanation=(
            "The iterator helper expects a stack-resident iterator object in a precise initialized state."
        ),
        suggestion=(
            "Create and initialize the iterator in a stable stack slot and pass that exact slot through the protocol."
        ),
    )


def _trusted_arg_nullability_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Trusted or helper argument may still be NULL at the call site",
        explanation=(
            "The verifier still considers the argument nullable, so the helper or kfunc contract is not satisfied."
        ),
        suggestion=(
            "Add a dominating null check and only make the call on the refined non-null branch."
        ),
    )


def _context_restriction_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Kernel, JIT, or execution context does not allow this helper or kfunc here",
        explanation=(
            "The requested helper-like operation is rejected because the current hook, callback, "
            "sleepability state, or JIT support does not admit it."
        ),
        suggestion=(
            "Use a helper or kfunc that is valid for this hook and execution context, or gate "
            "the feature on the relevant kernel capability."
        ),
    )


def _map_bounds_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Map value access exceeds the bounds proven for the target object",
        explanation=(
            "The verifier sees a map-value access whose offset or size can exceed the object's "
            "proven extent at the reject site."
        ),
        suggestion=(
            "Prove the offset range before the access or clamp the derived offset into the map value size."
        ),
    )


def _dynptr_storage_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Dynptr storage, offset, or release contract is violated",
        explanation=(
            "The dynptr must stay at a fixed verifier-visible storage location and obey a strict "
            "single-acquire/single-release protocol."
        ),
        suggestion=(
            "Keep the dynptr at a fixed stack offset, avoid derived dynptr pointers, and release it exactly once."
        ),
    )


def _irq_flag_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="IRQ flag protocol or stack placement is invalid",
        explanation=(
            "The helper expects an IRQ flag object in a specific initialized state and stack location."
        ),
        suggestion=(
            "Keep the IRQ flag in a dedicated stack slot and pair save and restore operations correctly."
        ),
    )


def _btf_metadata_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="BTF or reference metadata is missing, malformed, or incompatible",
        explanation=(
            "The verifier cannot validate the helper or reference contract because the required "
            "BTF metadata is missing or does not match the running kernel."
        ),
        suggestion=(
            "Regenerate the object's BTF metadata and ensure the object, kernel, and helper metadata align."
        ),
    )


def _mutable_global_details() -> DiagnosticDetails:
    return DiagnosticDetails(
        summary="Mutable global or static storage is unsupported in this environment",
        explanation=(
            "The target loader or kernel only supports read-only global data for this program configuration."
        ),
        suggestion=(
            "Move mutable state into an explicit BPF map or gate the feature on runtime support."
        ),
    )


def _register_contract_details(error_line: str) -> DiagnosticDetails:
    type_match = TYPE_EXPECTED_RE.search(error_line)
    if type_match is not None:
        register, actual, expected = type_match.groups()
        return DiagnosticDetails(
            summary=f"{register} has verifier type `{actual}` but the use requires `{expected}`",
            explanation=(
                "The helper argument, pointer use, or register contract expects a different "
                "verifier type than the register currently carries."
            ),
            suggestion=(
                "Reload or reconstruct the required typed value immediately before the use and "
                "avoid converting it into a generic scalar or invalid pointer state."
            ),
        )

    context_match = INVALID_BPF_CONTEXT_RE.search(error_line)
    if context_match is not None:
        off = context_match.group("off")
        size = context_match.group("size")
        detail = f" at offset {off} size {size}" if off is not None and size is not None else ""
        return DiagnosticDetails(
            summary=f"Program reads a context field that is unavailable for this hook{detail}",
            explanation=(
                "The verifier rejects the context access because this program type does not "
                "expose that field at the requested offset."
            ),
            suggestion=(
                "Use only context fields guaranteed for this hook or switch to a program type "
                "whose context exposes the required field."
            ),
        )

    lowered = error_line.lower()
    if "pointer comparison prohibited" in lowered:
        summary = "Pointer comparison is not allowed for this pointer kind"
    elif "!read_ok" in lowered:
        summary = "Register is read before the verifier has seen it initialized on this path"
    elif "misaligned stack access" in lowered:
        summary = "Stack access alignment does not satisfy the verifier contract"
    else:
        summary = "Register, stack slot, or helper argument violates a verifier contract"

    return DiagnosticDetails(
        summary=summary,
        explanation=(
            "The final verifier line describes a concrete register, stack, or helper-argument "
            "contract mismatch that can be inferred from the error message alone."
        ),
        suggestion=(
            "Restore the required pointer or stack contract immediately before the use and keep "
            "stack accesses aligned, initialized, and typed as the helper expects."
        ),
    )


def _fallback_details(error_line: str) -> DiagnosticDetails:
    message = error_line or "Verifier rejection"
    return DiagnosticDetails(
        summary=message,
        explanation="The baseline could not map the final verifier message to a richer known rule.",
        suggestion="Inspect the matched verifier line and the rejected instruction near the end of the log.",
    )


def _details_for_pattern(
    matched_pattern: MatchedPattern | None,
    error_line: str,
) -> DiagnosticDetails:
    if matched_pattern is None:
        return _fallback_details(error_line)

    error_id = matched_pattern.pattern.error_id
    if error_id == "BPFIX-E001":
        return _packet_bounds_details()
    if error_id == "BPFIX-E002":
        return _nullable_pointer_details()
    if error_id == "BPFIX-E003":
        return _stack_read_details()
    if error_id == "BPFIX-E004":
        return _reference_lifetime_details()
    if error_id == "BPFIX-E005":
        return _scalar_range_details(error_line)
    if error_id == "BPFIX-E006":
        return _provenance_loss_details()
    if error_id in {"BPFIX-E007", "BPFIX-E008", "BPFIX-E018"}:
        return _verifier_limit_details(error_line)
    if error_id == "BPFIX-E009":
        return _helper_unavailable_details()
    if error_id == "BPFIX-E010":
        return _verifier_false_positive_details()
    if error_id == "BPFIX-E011":
        return _scalar_pointer_details()
    if error_id == "BPFIX-E012":
        return _dynptr_protocol_details()
    if error_id == "BPFIX-E013":
        return _discipline_details()
    if error_id == "BPFIX-E014":
        return _iterator_details()
    if error_id == "BPFIX-E015":
        return _trusted_arg_nullability_details()
    if error_id == "BPFIX-E016":
        return _context_restriction_details()
    if error_id == "BPFIX-E017":
        return _map_bounds_details()
    if error_id == "BPFIX-E019":
        return _dynptr_storage_details()
    if error_id == "BPFIX-E020":
        return _irq_flag_details()
    if error_id == "BPFIX-E021":
        return _btf_metadata_details()
    if error_id == "BPFIX-E022":
        return _mutable_global_details()
    if error_id == "BPFIX-E023":
        return _register_contract_details(error_line)
    return _fallback_details(error_line)


_SCHEMA_ACTION_BY_FIX_ACTION = {
    "ADD_BOUNDS_GUARD": "ADD_BOUNDS_GUARD",
    "ADD_NULL_CHECK": "ADD_NULL_CHECK",
    "INSERT_RANGE_CLAMP": "TIGHTEN_RANGE",
    "FORCE_UNSIGNED_CAST": "TIGHTEN_RANGE",
    "TIGHTEN_OFFSET_RANGE": "TIGHTEN_RANGE",
    "RELOAD_PACKET_POINTER_AFTER_CHECK": "REWRITE_POINTER_ARITH",
    "RELOAD_POINTER_FROM_VERIFIED_BASE": "REWRITE_POINTER_ARITH",
    "KEEP_POINTER_AND_OFFSET_SEPARATE": "REWRITE_POINTER_ARITH",
    "AVOID_SPILL_RELOAD": "REWRITE_POINTER_ARITH",
    "REDUCE_CONTROL_FLOW_BRANCHING": "SIMPLIFY_CFG",
    "HOIST_COMMON_CHECKS": "SIMPLIFY_CFG",
    "STRENGTHEN_LOOP_BOUND": "SIMPLIFY_CFG",
    "ADD_MONOTONIC_COUNTER_GUARD": "SIMPLIFY_CFG",
    "MOVE_RELEASE_TO_ALL_PATHS": "SIMPLIFY_CFG",
    "MOVE_DISALLOWED_CALL_OUTSIDE_CRITICAL_SECTION": "SIMPLIFY_CFG",
    "SWITCH_HELPER": "GATE_BY_KERNEL_CAPABILITY",
    "GATE_ON_KERNEL_FEATURE": "GATE_BY_KERNEL_CAPABILITY",
    "GATE_ON_PROGRAM_CONTEXT": "GATE_BY_KERNEL_CAPABILITY",
    "MINIMIZE_REPRODUCER": "INVESTIGATE_VERIFIER_BUG",
    "BISECT_KERNEL": "INVESTIGATE_VERIFIER_BUG",
}


def _candidate_repairs(
    pattern: ErrorPattern | None,
    suggestion: str,
) -> list[dict[str, str]]:
    if pattern is None:
        return [{"action": "UNKNOWN", "rationale": suggestion, "patch_hint": suggestion}]

    repairs: list[dict[str, str]] = []
    seen: set[str] = set()
    for fix_action in pattern.example_fix_actions:
        schema_action = _SCHEMA_ACTION_BY_FIX_ACTION.get(fix_action, "UNKNOWN")
        if schema_action in seen:
            continue
        repairs.append(
            {
                "action": schema_action,
                "rationale": suggestion,
                "patch_hint": suggestion,
            }
        )
        seen.add(schema_action)
        if len(repairs) >= 2:
            break

    if not repairs:
        repairs.append({"action": "UNKNOWN", "rationale": suggestion, "patch_hint": suggestion})
    return repairs


def _source_span_payload(
    context: DiagnosticContext,
    *,
    fallback_snippet: str,
) -> dict[str, object]:
    line_number = (context.instruction_index + 1) if context.instruction_index is not None else 1
    payload: dict[str, object] = {
        "path": "<bytecode>",
        "line_start": line_number,
        "line_end": line_number,
        "snippet": fallback_snippet,
    }

    location = context.source_location
    if location is None:
        return payload

    if location.path is not None and location.line is not None:
        payload["path"] = location.path
        payload["line_start"] = location.line
        payload["line_end"] = location.line
    if location.column is not None:
        payload["column_start"] = location.column
        payload["column_end"] = location.column
    if location.snippet:
        payload["snippet"] = location.snippet
    return payload


def _evidence_items(
    context: DiagnosticContext,
    *,
    snippet: str,
) -> list[dict[str, object]]:
    evidence: list[dict[str, object]] = []
    for line in context.evidence_lines or (snippet,):
        item: dict[str, object] = {"kind": "verifier_log", "detail": line}
        if line == context.error_line and context.instruction_index is not None:
            item["instruction_index"] = context.instruction_index
        evidence.append(item)

    location = context.source_location
    if location is not None and location.path is not None and location.line is not None:
        evidence.append(
            {
                "kind": "source_map",
                "detail": f"{location.path}:{location.line}",
            }
        )
    return evidence


def generate_baseline_diagnostic(
    verifier_log: str,
    catalog_path: str | None = None,
) -> DiagnosticOutput:
    """Emit a schema-compatible diagnostic without trace analysis."""

    context = extract_diagnostic_context(verifier_log, catalog_path=catalog_path)
    matched_pattern = context.matched_pattern
    pattern = matched_pattern.pattern if matched_pattern is not None else None

    error_id = pattern.error_id if pattern is not None else UNKNOWN_ERROR_ID
    failure_class = classify_failure_class(context.error_line, matched_pattern)
    details = _details_for_pattern(matched_pattern, context.error_line)
    snippet = context.error_line or details.summary
    source_span = _source_span_payload(context, fallback_snippet=snippet)
    candidate_repairs = _candidate_repairs(pattern, details.suggestion)

    json_data: dict[str, object] = {
        "diagnostic_version": DIAGNOSTIC_VERSION,
        "error_id": error_id,
        "failure_class": failure_class,
        "message": details.summary,
        "source_span": source_span,
        "missing_obligation": details.explanation,
        "evidence": _evidence_items(context, snippet=snippet),
        "candidate_repairs": candidate_repairs,
        "metadata": {
            "engine": "regex_baseline",
            "proof_status": "unknown",
            "note": BASELINE_NOTE,
            "selection_reason": context.selection_reason,
            "explanation": details.explanation,
            "suggestion": details.suggestion,
            "catalog_obligation": pattern.likely_obligation if pattern is not None else None,
            "proof_spans": [
                {
                    "role": "rejected",
                    "path": str(source_span["path"]),
                    "line": int(source_span["line_start"]),
                    "source_text": str(source_span.get("snippet") or snippet),
                    "insn_range": [
                        context.instruction_index if context.instruction_index is not None else 0,
                        context.instruction_index if context.instruction_index is not None else 0,
                    ],
                    "register": None,
                    "state_change": None,
                    "reason": "matched from verifier tail messages without trace analysis",
                }
            ],
        },
    }

    if context.instruction_index is not None:
        json_data["verifier_site"] = {"instruction_index": context.instruction_index}
    if snippet:
        json_data["raw_log_excerpt"] = snippet
    if matched_pattern is not None:
        metadata = json_data["metadata"]
        assert isinstance(metadata, dict)
        metadata["matched_regex"] = matched_pattern.matched_regex
        metadata["matched_error_line"] = context.error_line
        metadata["matched_short_name"] = pattern.short_name if pattern is not None else None

    text = "\n".join(
        (
            f"error[{error_id}]: {failure_class} — {details.summary}",
            f"  = note: {BASELINE_NOTE}",
            f"  = help: {details.suggestion}",
        )
    )
    return DiagnosticOutput(text=text, json_data=json_data)
