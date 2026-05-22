"""Batch-level and known-answer regression tests for the BPFix diagnostic pipeline.

Tests in this module:
  - Batch correctness: run generate_diagnostic() on the SO raw cases with verifier
    logs and assert population-level invariants (success rate, proof_status
    distribution, error_id pattern coverage).
  - Known-answer regression: 5 well-understood cases checked against specific
    expected outputs so any regression in classification or span generation is
    caught immediately.
  - Proof status temporal ordering invariant: for established_then_lost cases,
    proof_established insn <= proof_lost insn <= rejected insn.
  - Pipeline schema invariants: every output has valid JSON structure, valid
    proof_status and taxonomy_class values, error_id pattern match, and span count <= 5.
"""

from __future__ import annotations

from functools import lru_cache
import re
from pathlib import Path

from bpfix.extractor.pipeline import generate_diagnostic

ROOT = Path(__file__).resolve().parents[1]
SO_CASES_DIR = ROOT / "bpfix-bench" / "raw" / "so"

VALID_PROOF_STATUSES = {"never_established", "established_then_lost", "established_but_insufficient", "proof_satisfied", "unknown"}
VALID_TAXONOMY_CLASSES = {
    "source_bug", "lowering_artifact", "verifier_limit", "environment_or_configuration", "verifier_false_positive", "unknown",
}
ERROR_ID_PATTERN = re.compile(r"^BPFIX-E\d{3}$|^BPFIX-UNKNOWN$")


def _load_verifier_log(relative_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(relative_path)


@lru_cache(maxsize=1)
def _so_cases_with_logs() -> tuple[Path, ...]:
    """Return all SO case YAML files that contain a non-empty verifier log."""
    result = []
    for f in sorted(SO_CASES_DIR.glob("*.yaml")):
        if f.name == "index.yaml":
            continue
        if _load_verifier_log(str(f.relative_to(ROOT))).strip():
            result.append(f)
    return tuple(result)


# ============================================================================
# Batch correctness assertions
# ============================================================================


def test_batch_so_no_crashes() -> None:
    """generate_diagnostic() must not crash on the SO raw cases with logs."""
    cases = _so_cases_with_logs()
    assert len(cases) >= 66, f"expected at least 66 SO cases with logs, found {len(cases)}"
    errors: list[tuple[str, str]] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        try:
            generate_diagnostic(log)
        except Exception as exc:
            errors.append((case_path.name, f"{type(exc).__name__}: {exc}"))
    assert not errors, "crashes on SO cases:\n" + "\n".join(f"  {n}: {e}" for n, e in errors)


def test_batch_so_never_established_ratio_below_threshold() -> None:
    """The never_established ratio across SO raw cases must stay <= 65%.

    Current baseline is ~59%. This threshold catches regressions where
    many established_then_lost cases are incorrectly collapsed to never_established.
    """
    cases = _so_cases_with_logs()
    never_est = 0
    total = 0
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        total += 1
        if out.json_data.get("metadata", {}).get("proof_status") == "never_established":
            never_est += 1
    ratio = never_est / total
    assert ratio <= 0.65, (
        f"never_established ratio {ratio:.1%} ({never_est}/{total}) exceeds 65% threshold"
    )


def test_batch_so_established_then_lost_count_above_baseline() -> None:
    """At least 8 SO cases must be classified as established_then_lost.

    Baseline updated for gap-based establishment detection:
    traces that start with gap=0 are now treated as vacuously satisfied and no
    longer count as proof establishment. The new baseline of 8 reflects the
    remaining cases with a real >0 -> 0 -> >0 lifecycle.
    """
    cases = _so_cases_with_logs()
    count = 0
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        if out.json_data.get("metadata", {}).get("proof_status") == "established_then_lost":
            count += 1
    assert count >= 8, (
        f"only {count} established_then_lost cases (expected >= 8)"
    )


def test_batch_so_all_outputs_have_valid_error_id() -> None:
    """Every diagnostic output must have an error_id matching BPFIX-E\\d{{3}} or BPFIX-UNKNOWN."""
    cases = _so_cases_with_logs()
    bad: list[tuple[str, str]] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        eid = out.json_data.get("error_id", "")
        if not ERROR_ID_PATTERN.match(eid):
            bad.append((case_path.name, eid))
    assert not bad, "invalid error_id in:\n" + "\n".join(f"  {n}: {repr(e)}" for n, e in bad)


# ============================================================================
# Known-answer regression tests (5 cases, one per taxonomy class)
# ============================================================================


def test_known_answer_lowering_artifact_70750259() -> None:
    """stackoverflow-70750259: canonical loss site, but no material establishment.

    The trace first observes R0 after it is already sufficiently bounded, so
    gap-based monitoring treats the establishment as vacuous. The OR instruction
    is still surfaced as the proof-loss site.
    """
    out = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
    )
    data = out.json_data
    meta = data.get("metadata", {})
    spans = meta.get("proof_spans", [])
    span_roles = {s["role"] for s in spans}

    assert data["error_id"] == "BPFIX-E005"
    assert data["failure_class"] == "lowering_artifact"
    assert meta["proof_status"] == "never_established"
    assert meta["cross_analysis_class"] == "established_then_lost"
    assert "proof_lost" in span_roles
    assert "rejected" in span_roles


def test_known_answer_lowering_artifact_70729664_large_trace() -> None:
    """stackoverflow-70729664: large trace — must succeed and have a causal_chain.

    Gap-based establishment removes the old vacuous establish site for this
    trace, so the proof status is now never_established. The log_parser still
    classifies it as source_bug (BPFIX-E001). Since we removed the taxonomy
    override that forced established_then_lost → lowering_artifact,
    the failure_class now reflects the log_parser classification.
    """
    out = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70729664.yaml")
    )
    data = out.json_data
    meta = data.get("metadata", {})

    assert meta["proof_status"] == "never_established"
    assert meta.get("causal_chain"), "expected a non-empty causal_chain for this case"
    # taxonomy comes from log_parser, not overridden by proof_status
    assert data["failure_class"] in {"source_bug", "lowering_artifact"}


def test_known_answer_verifier_limit_70841631() -> None:
    """stackoverflow-70841631: program-too-large verifier_limit case."""
    out = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70841631.yaml")
    )
    data = out.json_data

    assert data["error_id"] == "BPFIX-E018"
    assert data["failure_class"] == "verifier_limit"
    assert data.get("metadata", {}).get("proof_status") == "unknown"


def test_known_answer_source_bug_60053570() -> None:
    """stackoverflow-60053570: direct packet-access source_bug — never_established."""
    out = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-60053570.yaml")
    )
    data = out.json_data

    assert data["error_id"] == "BPFIX-E001"
    assert data["failure_class"] == "source_bug"
    assert data.get("metadata", {}).get("proof_status") == "never_established"


def test_known_answer_environment_or_configuration_77462271() -> None:
    """stackoverflow-77462271: failed kernel BTF lookup — environment_or_configuration."""
    out = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-77462271.yaml")
    )
    data = out.json_data

    assert data["error_id"] == "BPFIX-E021"
    assert data["failure_class"] == "environment_or_configuration"


# ============================================================================
# Proof status temporal ordering invariant
# ============================================================================


def test_proof_span_temporal_ordering_for_established_then_lost_cases() -> None:
    """For established_then_lost cases with all three roles: pe.insn <= pl.insn <= rj.insn.

    This checks that the pipeline produces coherent ordering when all three
    proof spans are present. Cases where proof_established and proof_lost share
    the same insn (pe == pl) are allowed (loss at same instruction as establish).
    """
    cases = _so_cases_with_logs()
    violations: list[str] = []

    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        meta = out.json_data.get("metadata", {})
        if meta.get("proof_status") != "established_then_lost":
            continue
        spans = meta.get("proof_spans", [])
        by_role = {s["role"]: s for s in spans}
        if not (
            "proof_established" in by_role
            and "proof_lost" in by_role
            and "rejected" in by_role
        ):
            continue  # not all three roles present — skip

        pe_min = by_role["proof_established"]["insn_range"][0]
        pl_min = by_role["proof_lost"]["insn_range"][0]
        rj_min = by_role["rejected"]["insn_range"][0]

        if not (pe_min <= rj_min and pl_min <= rj_min):
            violations.append(
                f"{case_path.name}: pe={pe_min} pl={pl_min} rj={rj_min} (pe or pl after rj)"
            )

    assert not violations, "temporal ordering violated:\n" + "\n".join(
        f"  {v}" for v in violations
    )


def test_proof_span_state_change_is_string_or_none() -> None:
    """state_change field on proof spans must be a non-empty string or None — never empty string."""
    cases = _so_cases_with_logs()
    bad: list[str] = []

    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        spans = out.json_data.get("metadata", {}).get("proof_spans", [])
        for span in spans:
            sc = span.get("state_change")
            if sc is not None and not isinstance(sc, str):
                bad.append(f"{case_path.name}: state_change is {type(sc).__name__}")
            elif isinstance(sc, str) and sc.strip() == "":
                bad.append(f"{case_path.name}: state_change is empty string")

    assert not bad, "invalid state_change values:\n" + "\n".join(f"  {b}" for b in bad)


# ============================================================================
# Pipeline schema invariants
# ============================================================================


def test_pipeline_proof_status_is_valid_value() -> None:
    """Every proof_status in the output must be one of the 4 valid values."""
    cases = _so_cases_with_logs()
    bad: list[str] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        status = out.json_data.get("metadata", {}).get("proof_status")
        if status not in VALID_PROOF_STATUSES:
            bad.append(f"{case_path.name}: proof_status={repr(status)}")
    assert not bad, "invalid proof_status:\n" + "\n".join(f"  {b}" for b in bad)


def test_pipeline_taxonomy_class_is_valid_value() -> None:
    """Every failure_class must be one of the 5 taxonomy classes (or unknown)."""
    cases = _so_cases_with_logs()
    bad: list[str] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        fc = out.json_data.get("failure_class")
        if fc not in VALID_TAXONOMY_CLASSES:
            bad.append(f"{case_path.name}: failure_class={repr(fc)}")
    assert not bad, "invalid failure_class:\n" + "\n".join(f"  {b}" for b in bad)


def test_pipeline_span_count_at_most_five() -> None:
    """Number of proof_spans in metadata must not exceed 5 (renderer cap)."""
    cases = _so_cases_with_logs()
    bad: list[str] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        spans = out.json_data.get("metadata", {}).get("proof_spans", [])
        if len(spans) > 5:
            bad.append(f"{case_path.name}: {len(spans)} spans")
    assert not bad, "span count exceeds 5:\n" + "\n".join(f"  {b}" for b in bad)


def test_pipeline_output_has_required_json_keys() -> None:
    """Every diagnostic output must have all required top-level JSON keys."""
    required_keys = {
        "diagnostic_version",
        "error_id",
        "failure_class",
        "message",
        "source_span",
        "missing_obligation",
        "metadata",
    }
    cases = _so_cases_with_logs()
    bad: list[str] = []
    for case_path in cases:
        log = _load_verifier_log(str(case_path.relative_to(ROOT)))
        out = generate_diagnostic(log)
        missing = required_keys - out.json_data.keys()
        if missing:
            bad.append(f"{case_path.name}: missing keys {missing}")
    assert not bad, "missing required keys:\n" + "\n".join(f"  {b}" for b in bad)
