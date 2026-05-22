"""Specific verifier-line parsing and reject refinement helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .log_parser import ParsedLog


REGISTER_TYPE_EXPECTED_RE = re.compile(
    r"(?P<register>R\d+)\s+type=(?P<actual>[^,\s]+)\s+expected=(?P<expected>.+)",
    re.IGNORECASE,
)
ARG_POINTER_CONTRACT_RE = re.compile(
    r"arg#(?P<arg_index>\d+)\s+pointer type\s+(?P<actual>.+?)\s+must point to\s+(?P<expected>.+)",
    re.IGNORECASE,
)
ARG_EXPECTED_CONTRACT_RE = re.compile(
    r"arg#(?P<arg_index>\d+)\s+expected\s+(?P<expected>.+)",
    re.IGNORECASE,
)
CALL_TARGET_RE = re.compile(r"\bcall\s+(?P<target>[a-zA-Z0-9_]+)#(?P<helper_id>\d+)\b")
NULL_ARG_RE = re.compile(
    r"Possibly NULL pointer passed to (?P<target>helper|trusted) arg(?P<arg_index>\d+)",
    re.IGNORECASE,
)
ITERATOR_PROTOCOL_RE = re.compile(
    r"expected\s+(?P<state>an initialized|uninitialized)\s+(?P<iter_type>[a-zA-Z0-9_]+)\s+as arg\s*#(?P<arg_index>\d+)",
    re.IGNORECASE,
)
DYNPTR_INITIALIZED_RE = re.compile(
    r"expected an initialized dynptr as arg\s*#(?P<arg_index>\d+)",
    re.IGNORECASE,
)
UNACQUIRED_REFERENCE_RE = re.compile(
    r"arg\s+(?P<arg_index>\d+)\s+is an unacquired reference",
    re.IGNORECASE,
)
HELPER_UNAVAILABLE_RE = re.compile(
    r"program of this type cannot use helper\s+(?P<helper>[a-zA-Z0-9_]+)#(?P<helper_id>\d+)",
    re.IGNORECASE,
)
UNKNOWN_FUNC_RE = re.compile(
    r"unknown func\s+(?P<helper>[a-zA-Z0-9_]+)#(?P<helper_id>\d+)",
    re.IGNORECASE,
)
RAW_CALLBACK_CONTEXT_RE = re.compile(
    r"cannot (?:call|be called).*\bfrom callback",
    re.IGNORECASE,
)
REFERENCE_LEAK_RE = re.compile(r"(?:reference leak|unreleased reference)", re.IGNORECASE)
TYPE_LABELS = {
    "fp": "a stack pointer",
    "inv": "an untyped scalar value",
    "scalar": "a scalar value",
    "struct with scalar": "a struct with scalar fields",
    "map_ptr": "a map pointer",
    "map_value": "a map-value pointer",
    "map_key": "a map-key pointer",
    "pkt": "a packet pointer",
    "pkt_meta": "a packet-metadata pointer",
    "ptr": "a generic pointer",
    "ptr_": "a typed pointer",
    "pointer to stack": "a stack pointer",
    "const struct bpf_dynptr": "a const struct bpf_dynptr",
    "trusted_ptr_": "a trusted pointer",
    "rcu_ptr_": "an RCU-protected pointer",
    "ctx": "a context pointer",
    "unknown": "UNKNOWN data",
}


@dataclass(slots=True)
class SpecificContractMismatch:
    raw: str
    register: str | None = None
    arg_index: int | None = None
    actual: str | None = None
    expected_text: str = ""
    expected_tokens: tuple[str, ...] = ()


@dataclass(slots=True)
class SpecificRejectInfo:
    raw: str
    kind: str
    note: str | None = None
    help_text: str | None = None
    obligation_type: str | None = None
    obligation_required: str | None = None


def extract_specific_reject_info(parsed_log: ParsedLog) -> SpecificRejectInfo | None:
    surface_line = select_specific_verifier_line(parsed_log)
    if not surface_line:
        return None

    specific_contract = extract_specific_contract_mismatch(surface_line)
    if specific_contract is not None:
        return SpecificRejectInfo(
            raw=surface_line,
            kind="helper_arg",
            note=specific_contract_note(specific_contract),
            help_text=specific_contract_help(parsed_log, specific_contract),
            obligation_type="helper_arg",
            obligation_required=specific_contract.raw,
        )

    for builder in (
        _specific_null_reject_info,
        _specific_iterator_reject_info,
        _specific_dynptr_reject_info,
        _specific_execution_context_reject_info,
        _specific_reference_leak_reject_info,
        _specific_env_helper_reject_info,
    ):
        result = builder(parsed_log, surface_line)
        if result is not None:
            return result

    if surface_line != (parsed_log.error_line or ""):
        return SpecificRejectInfo(
            raw=surface_line,
            kind="verifier_reject",
            note=f"Verifier reject line: {surface_line}",
        )
    return None


def select_specific_verifier_line(parsed_log: ParsedLog) -> str | None:
    best_line = normalize_verifier_line(parsed_log.error_line)
    best_score = specific_reject_line_score(best_line)

    for line in parsed_log.lines:
        candidate = normalize_verifier_line(line)
        if not candidate:
            continue
        score = specific_reject_line_score(candidate)
        if score > best_score or (score == best_score and score > 0 and candidate != best_line):
            best_line = candidate
            best_score = score

    return best_line or None


def normalize_verifier_line(line: str | None) -> str:
    if not line:
        return ""
    normalized = " ".join(line.strip().split())
    while normalized.startswith(":"):
        normalized = normalized[1:].lstrip()
    if not normalized or normalized.startswith(";"):
        return ""
    if re.match(r"^\d+:\s+\([0-9a-f]{2}\)", normalized, flags=re.IGNORECASE):
        return ""
    return normalized


def specific_reject_line_score(line: str) -> int:
    if not line:
        return -1

    lowered = line.lower()
    if extract_specific_contract_mismatch(line) is not None:
        return 100
    if NULL_ARG_RE.search(line):
        return 95
    if ITERATOR_PROTOCOL_RE.search(line):
        return 94
    if DYNPTR_INITIALIZED_RE.search(line):
        return 94
    if (
        "unacquired reference" in lowered
        or "cannot pass in dynptr at an offset" in lowered
        or "dynptr has to be at a constant offset" in lowered
        or "cannot overwrite referenced dynptr" in lowered
    ):
        return 93
    if "function calls are not allowed while holding a lock" in lowered:
        return 92
    if "cannot call exception cb directly" in lowered or RAW_CALLBACK_CONTEXT_RE.search(line):
        return 92
    if REFERENCE_LEAK_RE.search(line):
        return 92
    if HELPER_UNAVAILABLE_RE.search(line):
        return 91
    if UNKNOWN_FUNC_RE.search(line):
        return 90
    if "caller passes invalid args into func" in lowered:
        return 80
    if "reference type('unknown ')" in lowered and "size cannot be determined" in lowered:
        return 5
    if "invalid argument (os error 22)" in lowered:
        return 1
    return 0


def _specific_null_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> SpecificRejectInfo | None:
    match = NULL_ARG_RE.search(surface_line)
    if match is None:
        return None

    arg_index = int(match.group("arg_index"))
    target = match.group("target").lower()
    subject = f"arg{arg_index}"
    call_type = "trusted call site" if target == "trusted" else "helper call"
    obligation_type = "trusted_null_check" if target == "trusted" else "null_check"

    return SpecificRejectInfo(
        raw=surface_line,
        kind="null_check",
        note=(
            f"The verifier still treats {subject} as nullable at this {call_type}, "
            "so NULL can flow to the callee on one path."
        ),
        help_text=(
            f"Add a dominating null check for the value passed as {subject} and keep the "
            "checked register/value through the call."
        ),
        obligation_type=obligation_type,
        obligation_required=f"{subject} not nullable",
    )


def _specific_iterator_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> SpecificRejectInfo | None:
    match = ITERATOR_PROTOCOL_RE.search(surface_line)
    if match is None:
        return None

    arg_index = int(match.group("arg_index"))
    iter_type = match.group("iter_type")
    helper_target = (last_helper_target(parsed_log.raw_log) or "").lower()
    needs_initialized = "initialized" in match.group("state").lower()

    if needs_initialized:
        note = (
            f"This call expects an initialized {iter_type} in arg#{arg_index}, "
            "but that iterator slot was never created on this path."
        )
        if "destroy" in helper_target:
            help_text = (
                "Initialize the iterator with the matching create/new helper before destroy, "
                "or avoid destroy on an uninitialized iterator."
            )
        elif "next" in helper_target:
            help_text = (
                "Create the iterator before calling next, and only advance it after successful "
                "initialization."
            )
        else:
            help_text = (
                "Initialize the iterator with the matching create/new helper before this call, "
                "and keep the iterator live until its matching release/destroy."
            )
    else:
        note = (
            f"This call expects an uninitialized {iter_type} in arg#{arg_index}, "
            "but the iterator slot is already live."
        )
        help_text = (
            "Use a fresh iterator slot for creation, or destroy the existing iterator before "
            "reinitializing it."
        )

    return SpecificRejectInfo(
        raw=surface_line,
        kind="iterator_protocol",
        note=note,
        help_text=help_text,
        obligation_type="iterator_protocol",
        obligation_required=surface_line,
    )


def _specific_dynptr_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> SpecificRejectInfo | None:
    lowered = surface_line.lower()

    match = DYNPTR_INITIALIZED_RE.search(surface_line)
    if match is not None:
        arg_index = int(match.group("arg_index"))
        return SpecificRejectInfo(
            raw=surface_line,
            kind="dynptr_protocol",
            note=(
                f"This helper expects an initialized dynptr in arg#{arg_index}, "
                "but the dynptr was never successfully created on this path."
            ),
            help_text=(
                "Create the dynptr first and pass the original stack-backed dynptr slot "
                "to the helper."
            ),
            obligation_type="dynptr_protocol",
            obligation_required=surface_line,
        )

    if "cannot pass in dynptr at an offset" in lowered or "dynptr has to be at a constant offset" in lowered:
        return SpecificRejectInfo(
            raw=surface_line,
            kind="dynptr_protocol",
            note="The verifier requires the dynptr object to stay at its exact stack slot and constant offset.",
            help_text=(
                "Pass the dynptr at its exact stack slot / constant base address, not at a shifted "
                "or forged offset."
            ),
            obligation_type="dynptr_protocol",
            obligation_required=surface_line,
        )

    if "cannot overwrite referenced dynptr" in lowered:
        return SpecificRejectInfo(
            raw=surface_line,
            kind="dynptr_protocol",
            note="A live slice/reference still depends on this dynptr, so the dynptr cannot be overwritten yet.",
            help_text=(
                "Release or stop using derived slices/references before reinitializing or overwriting "
                "the dynptr."
            ),
            obligation_type="dynptr_protocol",
            obligation_required=surface_line,
        )

    if UNACQUIRED_REFERENCE_RE.search(surface_line) and "dynptr" in parsed_log.raw_log.lower():
        return SpecificRejectInfo(
            raw=surface_line,
            kind="dynptr_protocol",
            note="This call is using a dynptr reference that has already been released or was never acquired.",
            help_text=(
                "Release or discard the dynptr exactly once and stop using it after submit/discard/release."
            ),
            obligation_type="dynptr_protocol",
            obligation_required=surface_line,
        )

    return None


def _specific_execution_context_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> SpecificRejectInfo | None:
    lowered = surface_line.lower()
    if "function calls are not allowed while holding a lock" in lowered:
        return SpecificRejectInfo(
            raw=surface_line,
            kind="execution_context",
            note="The verifier rejects this call because the program is still holding a lock at the call site.",
            help_text=(
                "Move the subprogram/helper call out of the locked region, or unlock before calling."
            ),
            obligation_type="execution_context",
            obligation_required=surface_line,
        )

    if "cannot call exception cb directly" in lowered or RAW_CALLBACK_CONTEXT_RE.search(surface_line):
        return SpecificRejectInfo(
            raw=surface_line,
            kind="callback_context",
            note="This callback may only be invoked from the verifier-approved callback context.",
            help_text=(
                "Invoke the callback through its owning helper/iterator framework instead of calling "
                "it directly from program code."
            ),
            obligation_type="exception_callback_context",
            obligation_required=surface_line,
        )

    return None


def _specific_reference_leak_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> SpecificRejectInfo | None:
    if REFERENCE_LEAK_RE.search(surface_line) is None:
        return None

    return SpecificRejectInfo(
        raw=surface_line,
        kind="reference_leak",
        note="A referenced object remains live at exit on this path.",
        help_text=(
            "Release or destroy the acquired reference on every exit path, including early returns "
            "and callee-return paths."
        ),
        obligation_type="unreleased_reference",
        obligation_required=surface_line,
    )


def _specific_env_helper_reject_info(
    parsed_log: ParsedLog,
    surface_line: str,
) -> SpecificRejectInfo | None:
    match = HELPER_UNAVAILABLE_RE.search(surface_line)
    if match is not None:
        helper = match.group("helper")
        return SpecificRejectInfo(
            raw=surface_line,
            kind="env_helper",
            note=f"This program type does not permit the helper {helper}#{match.group('helper_id')}.",
            help_text=(
                f"Use a helper allowed in this program type, or move the logic to a program type "
                f"that permits {helper}."
            ),
        )

    match = UNKNOWN_FUNC_RE.search(surface_line)
    if match is None:
        return None

    helper = match.group("helper")
    if helper == "bpf_get_current_pid_tgid":
        help_text = (
            "Read the PID from the program context instead of calling bpf_get_current_pid_tgid "
            "in this program type."
        )
    else:
        help_text = (
            f"Use a supported helper in this program type/kernel, or target an environment that "
            f"provides {helper}."
        )

    return SpecificRejectInfo(
        raw=surface_line,
        kind="env_helper",
        note=f"The target verifier context does not expose the helper {helper}#{match.group('helper_id')}.",
        help_text=help_text,
    )


def extract_specific_contract_mismatch(error_line: str | None) -> SpecificContractMismatch | None:
    if not error_line:
        return None

    raw = " ".join(error_line.strip().split())
    match = REGISTER_TYPE_EXPECTED_RE.search(raw)
    if match:
        expected_text = match.group("expected").strip()
        return SpecificContractMismatch(
            raw=raw,
            register=match.group("register").upper(),
            actual=match.group("actual").strip(),
            expected_text=expected_text,
            expected_tokens=split_expected_tokens(expected_text),
        )

    match = ARG_POINTER_CONTRACT_RE.search(raw)
    if match:
        expected_text = match.group("expected").strip()
        return SpecificContractMismatch(
            raw=raw,
            arg_index=int(match.group("arg_index")),
            actual=match.group("actual").strip(),
            expected_text=expected_text,
            expected_tokens=split_expected_tokens(expected_text),
        )

    match = ARG_EXPECTED_CONTRACT_RE.search(raw)
    if match:
        expected_text = match.group("expected").strip()
        return SpecificContractMismatch(
            raw=raw,
            arg_index=int(match.group("arg_index")),
            expected_text=expected_text,
            expected_tokens=split_expected_tokens(expected_text),
        )

    return None


def split_expected_tokens(expected_text: str) -> tuple[str, ...]:
    tokens: list[str] = []
    for token in re.split(
        r",\s*(?:or\s+)?|\s+or\s+",
        expected_text.strip(),
        flags=re.IGNORECASE,
    ):
        cleaned = token.strip().strip(".")
        if cleaned:
            tokens.append(cleaned.lower())
    return tuple(tokens)


def specific_contract_note(contract: SpecificContractMismatch) -> str:
    subject = contract.register or (
        f"arg#{contract.arg_index}" if contract.arg_index is not None else "this argument"
    )
    expected = humanize_expected(contract)
    if contract.actual:
        actual = describe_observed_type_token(contract.actual)
        return f"The verifier sees {subject} as {actual}, but this call requires {expected}."
    return f"This call requires {expected}."


def specific_contract_help(
    parsed_log: ParsedLog,
    contract: SpecificContractMismatch,
) -> str | None:
    expected = set(contract.expected_tokens)
    helper_target = last_helper_target(parsed_log.raw_log)

    if "map_ptr" in expected:
        return (
            "Pass the map object itself as this argument, not a pointer to a map value. "
            "Preserve the loader-generated map reference so the verifier sees map_ptr."
        )

    if "fp" in expected:
        if helper_target == "bpf_map_update_elem" and contract.register == "R2":
            return (
                "Pass a stack-backed key pointer as arg2 instead of NULL or a scalar value. "
                "If this map type has no key, use the map API that matches that map type "
                "instead of bpf_map_update_elem()."
            )
        return "Pass a stack pointer for this argument, not a map, packet, or scalar value."

    lowered_expected = contract.expected_text.lower()
    if "scalar" in expected or "struct with scalar" in lowered_expected:
        return (
            "Pass data whose pointee is scalar-compatible, or change the kfunc signature to "
            "accept the exact BTF-typed object you pass. Casts alone will not satisfy the "
            "verifier-visible contract."
        )

    if "pointer to stack" in lowered_expected and "bpf_dynptr" in lowered_expected:
        return (
            "Pass a stack pointer or a const struct bpf_dynptr for this argument. "
            "Plain scalars or unrelated pointers will not satisfy the contract."
        )

    if "trusted_ptr_" in expected or "trusted" in lowered_expected:
        return (
            "Pass the original trusted pointer from the verifier-approved source, and keep the "
            "null/trust refinement on the exact register that reaches the call."
        )

    if "rcu_ptr_" in expected or "rcu" in lowered_expected:
        return (
            "Acquire the RCU-protected pointer through the expected helper/kfunc path and keep "
            "it in its verifier-tracked typed register until the call."
        )

    if "ptr_" in expected or "pointer type" in lowered_expected:
        return (
            "Pass the exact typed pointer object the callee expects. Reconstructing it from a "
            "scalar or incompatible pointee will not satisfy the verifier."
        )

    if "map_value" in expected or "map value" in lowered_expected:
        return (
            "Pass a map-value pointer from a successful lookup, and keep the checked lookup "
            "result on the register that reaches the call."
        )

    if "pkt" in expected or "packet" in lowered_expected:
        return (
            "Pass the packet pointer that still carries verifier range proof, and avoid copying "
            "it through arithmetic or unchecked aliases before the call."
        )

    return None


def last_helper_target(raw_log: str) -> str | None:
    matches = list(CALL_TARGET_RE.finditer(raw_log))
    if not matches:
        return None
    return matches[-1].group("target")


def humanize_expected(contract: SpecificContractMismatch) -> str:
    if contract.expected_tokens:
        labels = [describe_expected_token(token) for token in contract.expected_tokens]
        if len(labels) == 1:
            return labels[0]
        return "one of: " + ", ".join(labels)
    return contract.expected_text or "a verifier-compatible argument"


def describe_type_token(token: str) -> str:
    lowered = token.lower()
    for prefix, label in TYPE_LABELS.items():
        if lowered == prefix or lowered.startswith(prefix):
            return label
    return token


def describe_expected_token(token: str) -> str:
    lowered = token.lower()
    if lowered in {"trusted_ptr_", "trusted"}:
        return "a trusted pointer"
    if lowered in {"rcu_ptr_", "rcu"}:
        return "an RCU-protected pointer"
    if lowered in {"ptr_", "ptr"}:
        return "the exact typed pointer"
    if lowered == "map_ptr":
        return "a map pointer"
    if lowered == "map_value":
        return "a map-value pointer"
    if lowered == "pkt":
        return "a packet pointer"
    if lowered == "fp":
        return "a stack pointer"
    if lowered == "scalar":
        return "a scalar value"
    return describe_type_token(token)


def describe_observed_type_token(token: str) -> str:
    description = describe_type_token(token)
    if description.lower() == token.lower():
        return description
    return f"{description} ({token})"
