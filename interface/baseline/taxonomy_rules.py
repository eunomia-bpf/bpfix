"""Simple message-only taxonomy rules for the regex baseline."""

from __future__ import annotations

import re

from .error_patterns import MatchedPattern

LOWERING_ARTIFACT_RE = re.compile(
    r"unbounded min value|unbounded memory access|"
    r"min value is negative|math between .* pointer and register with unbounded|"
    r"value is outside of the allowed memory range",
    flags=re.IGNORECASE,
)
VERIFIER_LIMIT_RE = re.compile(
    r"too many states|complexity limit|loop is not bounded|back-edge|"
    r"BPF program is too large|combined stack size|stack depth .* exceeds",
    flags=re.IGNORECASE,
)
ENVIRONMENT_OR_CONFIGURATION_RE = re.compile(
    r"unknown func|program of this type cannot use helper|helper call is not allowed|"
    r"attach_btf_id is not a function|invalid btf|missing btf func_info|"
    r"failed to find kernel BTF type ID|only read from bpf_array is supported|"
    r"cannot be called from callback|sleepable|"
    r"jit does not support calling kfunc|btf_vmlinux is malformed|"
    r"unrecognized arg#\d+ type",
    flags=re.IGNORECASE,
)
VERIFIER_FALSE_POSITIVE_RE = re.compile(
    r"kernel BUG at kernel/bpf/verifier\.c|WARNING:.*verifier|invalid state transition",
    flags=re.IGNORECASE,
)


def classify_failure_class(
    error_message: str,
    matched_pattern: MatchedPattern | None,
) -> str:
    if matched_pattern is not None:
        return matched_pattern.pattern.failure_class
    if VERIFIER_FALSE_POSITIVE_RE.search(error_message):
        return "verifier_false_positive"
    if VERIFIER_LIMIT_RE.search(error_message):
        return "verifier_limit"
    if ENVIRONMENT_OR_CONFIGURATION_RE.search(error_message):
        return "environment_or_configuration"
    if LOWERING_ARTIFACT_RE.search(error_message):
        return "lowering_artifact"
    return "source_bug"
