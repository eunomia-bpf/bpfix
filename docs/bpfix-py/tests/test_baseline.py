from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest
import yaml

from bpfix.baseline.error_patterns import match_error_pattern
from bpfix.baseline.regex_diagnostic import generate_baseline_diagnostic
from bpfix.extractor.pipeline import generate_diagnostic

ROOT = Path(__file__).resolve().parents[1]


def _load_verifier_log(relative_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(relative_path)


def test_baseline_produces_valid_output_on_real_log() -> None:
    log = _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")

    output = generate_baseline_diagnostic(log)

    assert output.json_data["error_id"] == "BPFIX-E005"
    assert output.json_data["failure_class"] == "lowering_artifact"
    assert output.json_data["metadata"]["proof_status"] == "unknown"
    assert len(output.json_data["metadata"]["proof_spans"]) == 1
    assert output.json_data["metadata"]["proof_spans"][0]["role"] == "rejected"
    assert "unbounded min value" in output.json_data["raw_log_excerpt"]
    assert output.json_data["candidate_repairs"]
    assert "suggestion" in output.json_data["metadata"]


@pytest.mark.parametrize(
    ("message", "expected_id", "expected_class"),
    [
        (
            "math between pkt pointer and register with unbounded min value is not allowed",
            "BPFIX-E005",
            "lowering_artifact",
        ),
        (
            "Unreleased reference id=3 alloc_insn=10",
            "BPFIX-E004",
            "source_bug",
        ),
        (
            "loop is not bounded",
            "BPFIX-E008",
            "verifier_limit",
        ),
        (
            "unknown func bpf_get_current_pid_tgid#14",
            "BPFIX-E009",
            "environment_or_configuration",
        ),
        (
            "JIT does not support calling kfunc bpf_throw#73439",
            "BPFIX-E016",
            "environment_or_configuration",
        ),
        (
            "R1 min value is outside of the array range",
            "BPFIX-E005",
            "lowering_artifact",
        ),
    ],
)
def test_known_error_patterns_are_matched(
    message: str,
    expected_id: str,
    expected_class: str,
) -> None:
    matched = match_error_pattern(message)
    output = generate_baseline_diagnostic(message)

    assert matched is not None
    assert matched.pattern.error_id == expected_id
    assert output.json_data["error_id"] == expected_id
    assert output.json_data["failure_class"] == expected_class


def test_baseline_prefers_more_specific_tail_message_and_extracts_source_location() -> None:
    log = """
; ret = bpf_cpumask_populate((struct cpumask *)local, garbage, 8); @ cpumask_failure.c:255
18: (bf) r1 = r6
19: (b7) r2 = 1193046
20: (b7) r3 = 8
21: (85) call bpf_cpumask_populate#71435
R2 type=scalar expected=fp
arg#1 arg#2 memory, len pair leads to invalid memory access
processed 22 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
""".strip()

    output = generate_baseline_diagnostic(log)

    assert output.json_data["error_id"] == "BPFIX-E023"
    assert output.json_data["failure_class"] == "source_bug"
    assert output.json_data["source_span"]["path"] == "cpumask_failure.c"
    assert output.json_data["source_span"]["line_start"] == 255
    assert "R2 has verifier type" in output.json_data["message"]


def test_baseline_uses_limit_summary_when_tail_only_has_budget_signal() -> None:
    log = """
verification time 8906133 usec
stack depth 360
processed 496185 insns (limit 1000000) max_states_per_insn 4 total_states 6230 peak_states 6230 mark_read 3871
libbpf: prog 'test_builtin_memmove': failed to load: -524
libbpf: failed to load object 'builtins.o'
Error: failed to load object file
bpf_test.go:170: verifier error: load program: operation not supported:
\tprocessed 496185 insns (limit 1000000) max_states_per_insn 4 total_states 6230 peak_states 6230 mark_read 3871
""".strip()

    output = generate_baseline_diagnostic(log)

    assert output.json_data["error_id"] == "BPFIX-E018"
    assert output.json_data["failure_class"] == "verifier_limit"
    assert "analysis budget" in output.json_data["message"]


def test_baseline_output_matches_bpfix_schema() -> None:
    schema = json.loads((ROOT / "bpfix" / "schema" / "diagnostic.json").read_text(encoding="utf-8"))
    log = _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")

    baseline_output = generate_baseline_diagnostic(log)
    bpfix_output = generate_diagnostic(log)

    Draft202012Validator(schema).validate(baseline_output.json_data)
    assert baseline_output.json_data["source_span"].keys() == bpfix_output.json_data["source_span"].keys()
    assert "proof_status" in baseline_output.json_data["metadata"]
    assert "proof_spans" in baseline_output.json_data["metadata"]
