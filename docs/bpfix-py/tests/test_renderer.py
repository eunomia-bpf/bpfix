from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]

from bpfix.extractor.pipeline import generate_diagnostic
from bpfix.extractor.renderer import render_diagnostic
from bpfix.extractor.source_correlator import SourceSpan


def _load_verifier_log(relative_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(relative_path)


def _strip_btf_annotations(verifier_log: str) -> str:
    return "\n".join(
        line for line in verifier_log.splitlines() if not line.lstrip().startswith(";")
    )


def _proof_spans(output: Any) -> list[dict[str, object]]:
    return output.json_data["metadata"]["proof_spans"]


def test_generate_rust_style_lowering_artifact_with_btf_and_backtracking() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
    )

    assert "error[BPFIX-E005]" in output.text
    assert "lowering_artifact" in output.text
    assert "proof lost: OR operation destroys bounds" in output.text
    assert "if (data_end < (data + ext_len)) {" in output.text
    assert output.json_data["failure_class"] == "lowering_artifact"
    assert output.json_data["message"] == "never established"
    assert output.json_data["metadata"]["proof_status"] == "never_established"
    # Opcode-driven analysis identifies the scalar_bound obligation on R0
    assert output.json_data["metadata"]["obligation"]["type"] in {"packet_access", "scalar_bound"}
    assert any(
        span["role"] == "proof_lost"
        and span["insn_range"][0] == 22
        and span["reason"] == "OR operation destroys bounds"
        for span in _proof_spans(output)
    )
    assert any(
        span["role"] == "rejected" and "ext_len" in span["source_text"]
        for span in _proof_spans(output)
    )


def test_renderer_serializes_engine_causal_chain_in_metadata() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
    )

    causal_chain = output.json_data["metadata"]["causal_chain"]
    assert causal_chain
    assert all(isinstance(entry, dict) and "insn_idx" in entry and "reason" in entry for entry in causal_chain)
    assert any(entry["insn_idx"] == 22 for entry in causal_chain)
    assert all(isinstance(entry["reason"], str) and entry["reason"] for entry in causal_chain)


def test_generate_rust_style_source_bug_with_btf() -> None:
    output = generate_diagnostic(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-data-slice-missing-null-check2-raw-tp-8e533162.yaml"
        )
    )

    assert "error[BPFIX-E002]" in output.text
    assert "dynptr_fail.c" in output.text
    assert "*data2 = 3;" in output.text
    assert output.json_data["failure_class"] == "source_bug"
    assert output.json_data["metadata"]["proof_status"] == "never_established"
    assert "null" in output.json_data["missing_obligation"].lower()
    assert output.json_data["metadata"]["obligation"]["type"] in {
        "null_check",
        "non_null_dereference",
    }
    assert any(
        span["role"] == "rejected" and span["path"] == "dynptr_fail.c" and span["line"] == 391
        for span in _proof_spans(output)
    )


def test_generate_rust_style_reuses_btf_location_for_multi_insn_call_site() -> None:
    output = generate_diagnostic(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-skb-invalid-ctx-fentry-fentry-skb-tx-error-17cea403.yaml"
        )
    )

    assert any(
        span["role"] == "rejected"
        and span["path"] == "dynptr_fail.c"
        and span["line"] == 1265
        and "bpf_dynptr_from_skb" in span["source_text"]
        for span in _proof_spans(output)
    )


def test_renderer_emits_rejected_span_when_trace_has_no_instructions() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-48267671.yaml")
    )

    spans = _proof_spans(output)
    assert spans
    assert spans[0]["role"] == "rejected"
    assert "EINVAL For BPF_PROG_LOAD" in spans[0]["source_text"]


def test_renderer_uses_structured_state_fields_without_reparsing_state_change() -> None:
    output = render_diagnostic(
        error_id="BPFIX-TEST",
        taxonomy_class="lowering_artifact",
        proof_status="established_then_lost",
        spans=[
            SourceSpan(
                file="test.c",
                line=7,
                source_text="x = *ptr;",
                insn_range=(7, 7),
                role="proof_lost",
                register="R1",
                state_change="R1: pkt -> scalar",
                reason="pointer provenance was degraded to a scalar",
                state_before="pkt(range=8)",
                state_after="scalar(unbounded)",
            )
        ],
        obligation=None,
        note=None,
        help_text=None,
    )

    assert output.json_data["observed_state"]["registers"]["R1"] == "scalar(unbounded)"


def test_renderer_crypto_acquire_b8afbe98_produces_rejected_span() -> None:
    """kernel-selftest-crypto-acquire: unreleased-reference case must produce at least a rejected span.

    The expected verifier message for this case is 'Unreleased reference' (E004,
    source_bug).  Previously the spurious BTF probe line
    'arg#0 reference type(UNKNOWN) size cannot be determined: -22' was selected as
    the error line and mis-mapped to E021 / environment_or_configuration.  After the BTF_PROBE_NOISE_RE
    penalisation the correct 'Unreleased reference' error line is selected instead.
    """
    output = generate_diagnostic(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98.yaml"
        )
    )

    roles = {span["role"] for span in _proof_spans(output)}
    # Must have at least a rejected span — no false lifecycle spans
    assert "rejected" in roles
    # The real error is Unreleased reference (E004 / source_bug), not environment_or_configuration
    assert output.json_data["failure_class"] == "source_bug"
    assert output.json_data["error_id"] == "BPFIX-E004"


def test_renderer_caps_redundant_spans_at_five() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
    )

    assert len(_proof_spans(output)) <= 5
    roles = {span["role"] for span in _proof_spans(output)}
    assert {"proof_lost", "rejected"} <= roles


def test_renderer_json_output_structure() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
    )

    data = output.json_data
    assert {
        "diagnostic_version",
        "error_id",
        "failure_class",
        "message",
        "source_span",
        "missing_obligation",
        "evidence",
        "candidate_repairs",
        "metadata",
    } <= data.keys()
    assert data["diagnostic_version"] == "0.1.0"
    assert data["evidence"] is not None
    assert data["candidate_repairs"]

    source_span = data["source_span"]
    assert {"path", "line_start", "line_end", "snippet"} <= source_span.keys()

    first_span = data["metadata"]["proof_spans"][0]
    assert {
        "role",
        "path",
        "line",
        "source_text",
        "insn_range",
        "state_change",
        "reason",
    } <= first_span.keys()


def test_renderer_keeps_dict_like_get_for_json_compatibility() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
    )

    assert output.get("metadata") == output.json_data["metadata"]


def test_renderer_falls_back_to_bytecode_without_btf_annotations() -> None:
    verifier_log = _strip_btf_annotations(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
    )
    output = generate_diagnostic(verifier_log)

    assert "┌─ <bytecode>" in output.text
    assert "r0 |= r6" in output.text
    assert "r5 += r0" in output.text
    assert output.json_data["source_span"]["path"] == "<bytecode>"
    assert any(span["source_text"] == "r0 |= r6" for span in _proof_spans(output))
    assert all(
        span["path"] is None and span["line"] is None for span in _proof_spans(output)
    )


def test_renderer_uses_bpftool_xlated_fallback_without_verifier_btf() -> None:
    verifier_log = _strip_btf_annotations(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
    )
    bpftool_xlated = """
    int parse_packet(void *data, void *data_end) {
       ; __u16 ext_len = __bpf_htons(ext->len); @ stackoverflow.c:22:9
       19: (71) r6 = *(u8 *)(r0 +2)
       20: (71) r0 = *(u8 *)(r0 +3)
       21: (67) r0 <<= 8
       22: (4f) r0 |= r6
       23: (dc) r0 = be16 r0
       ; if (data_end < (data + ext_len)) { @ stackoverflow.c:24:2
       24: (0f) r5 += r0
    }
    """
    output = generate_diagnostic(verifier_log, bpftool_xlated=bpftool_xlated)

    assert output.json_data["source_span"]["path"] == "stackoverflow.c"
    assert output.json_data["source_span"]["line_start"] == 24
    assert "data_end" in output.json_data["source_span"]["snippet"]
    assert any(
        span["path"] == "stackoverflow.c" and span["line"] == 22 for span in _proof_spans(output)
    )
    assert any(
        span["path"] == "stackoverflow.c" and span["line"] == 24 for span in _proof_spans(output)
    )


def test_renderer_drops_false_satisfied_status_for_round2_zero_trace_cases() -> None:
    cases = (
        "bpfix-bench/raw/so/stackoverflow-76994829.yaml",
        "bpfix-bench/raw/so/stackoverflow-77713434.yaml",
        "bpfix-bench/raw/so/stackoverflow-78591601.yaml",
    )

    for case_path in cases:
        output = generate_diagnostic(_load_verifier_log(case_path))
        assert output.json_data["metadata"]["proof_status"] in {"never_established", "unknown"}
        assert any(span["role"] == "rejected" for span in _proof_spans(output))


def test_renderer_preserves_engine_inferred_obligation_when_formal_analysis_returns_none() -> None:
    """BPFIX-E022 environment_or_configuration: 'only read from bpf_array is supported'.

    With the heuristics removed from the critical path, structural
    environment_or_configuration cases without an explicit error instruction keep
    proof_status='unknown' because no proof lifecycle can be established.
    """
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/gh/github-aya-rs-aya-1002.yaml")
    )

    assert output.json_data["metadata"]["proof_status"] == "unknown"
    # With opcode-driven analysis: no register-level obligation for structural environment_or_configuration.
    # The old approach produced a generic "safety_violation" placeholder; now we omit it.
    obligation = output.json_data.get("metadata", {}).get("obligation")
    if obligation is not None:
        # If obligation is present, it should be a meaningful type.
        assert obligation.get("type") not in {"", None}


def test_renderer_keeps_engine_obligation_when_unknown_engine_status_is_ignored() -> None:
    """BPFIX-E021 environment_or_configuration: BTF reference type error (no explicit error instruction).

    With opcode-driven analysis: no instruction is explicitly marked as is_error=True,
    so the opcode-driven lifecycle analysis does not apply. The proof_status is
    'unknown' or 'never_established' based on taxonomy. No register-level obligation
    is derived.
    """
    output = generate_diagnostic(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-add-dynptr-to-map1-raw-tp-2b5ac898.yaml"
        )
    )

    # proof_status is correctly unknown/never_established (no explicit error instruction)
    assert output.json_data["metadata"]["proof_status"] in {"unknown", "never_established"}
    # The obligation may be absent or may be derived from the error_id/taxonomy.
    obligation = output.json_data.get("metadata", {}).get("obligation")
    if obligation is not None:
        assert obligation.get("type") not in {"", None}


def test_renderer_preserves_specific_helper_contract_for_so_61945212() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-61945212.yaml")
    )

    assert "helper expected a stack pointer" in output.text
    assert "R2 as an untyped scalar value (inv)" in output.text
    assert "requires a stack pointer" in output.text
    assert "stack-backed key pointer as arg2" in output.text
    assert "required proof never established" not in output.text
    assert "Re-derive the required pointer or reference" not in output.text
    assert output.json_data["missing_obligation"] == "R2 type=inv expected=fp"
    assert output.json_data["metadata"]["obligation"] == {
        "type": "helper_arg",
        "required": "R2 type=inv expected=fp",
    }


def test_renderer_preserves_specific_helper_contract_for_so_70091221() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70091221.yaml")
    )

    assert "helper expected a map pointer" in output.text
    assert "R1 as a map-value pointer (map_value)" in output.text
    assert "requires a map pointer" in output.text
    assert "Pass the map object itself as this argument" in output.text
    assert "Re-derive the required pointer or reference" not in output.text
    assert output.json_data["missing_obligation"] == "R1 type=map_value expected=map_ptr"
    assert output.json_data["metadata"]["obligation"] == {
        "type": "helper_arg",
        "required": "R1 type=map_value expected=map_ptr",
    }


def test_renderer_preserves_specific_kfunc_contract_without_trace() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-79045875.yaml")
    )

    assert output.json_data["metadata"]["proof_status"] == "unknown"
    assert output.json_data["missing_obligation"] == (
        "arg#0 pointer type UNKNOWN must point to scalar, or struct with scalar"
    )
    assert output.json_data["metadata"]["obligation"] == {
        "type": "helper_arg",
        "required": "arg#0 pointer type UNKNOWN must point to scalar, or struct with scalar",
    }
    assert "kfunc expected a scalar-compatible pointee" in output.text
    assert "arg#0 as UNKNOWN data (UNKNOWN)" in output.text
    assert "requires one of: a scalar value, a struct with scalar fields" in output.text
    assert "Casts alone will not satisfy the verifier-visible contract" in output.text


def test_renderer_preserves_specific_iterator_protocol_error_from_raw_log() -> None:
    output = generate_diagnostic(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-iters-state-safety-destroy-without-creating-fail-raw-tp-a14b4d3a.yaml"
        )
    )

    assert "initialized iter_num" in output.text
    assert "create/new helper before destroy" in output.text
    assert "Regenerate BTF artifacts" not in output.text
    assert output.json_data["raw_log_excerpt"] == "expected an initialized iter_num as arg #0"


def test_renderer_preserves_specific_dynptr_release_error_from_raw_log() -> None:
    output = generate_diagnostic(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d.yaml"
        )
    )

    assert "unacquired reference" in output.json_data["raw_log_excerpt"]
    assert "released or was never acquired" in output.text
    assert "exactly once" in output.text
    assert "Regenerate BTF artifacts" not in output.text


def test_renderer_preserves_specific_lock_context_error_from_raw_log() -> None:
    output = generate_diagnostic(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-exceptions-fail-reject-subprog-with-lock-tc-f038a1b8.yaml"
        )
    )

    assert "still holding a lock" in output.text
    assert "unlock before calling" in output.text
    assert output.json_data["raw_log_excerpt"] == "function calls are not allowed while holding a lock"
    assert "Regenerate BTF artifacts" not in output.text


def test_renderer_preserves_specific_dynptr_argument_contract_from_raw_log() -> None:
    output = generate_diagnostic(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9.yaml"
        )
    )

    assert "requires one of: a stack pointer, a const struct bpf_dynptr" in output.text
    assert "Pass a stack pointer or a const struct bpf_dynptr" in output.text
    assert output.json_data["missing_obligation"] == (
        "arg#0 expected pointer to stack or const struct bpf_dynptr"
    )
    assert "Regenerate BTF artifacts" not in output.text


def test_renderer_preserves_specific_helper_unavailable_error_from_raw_log() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/gh/github-aya-rs-aya-1233.yaml")
    )

    assert "does not permit the helper bpf_probe_read#4" in output.text
    assert "permits bpf_probe_read" in output.text
    assert output.json_data["raw_log_excerpt"] == (
        "program of this type cannot use helper bpf_probe_read#4"
    )
    assert "tail calls" not in output.text


def test_renderer_preserves_specific_unknown_helper_error_from_raw_log() -> None:
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/gh/github-aya-rs-aya-864.yaml")
    )

    assert "does not expose the helper bpf_get_current_pid_tgid#14" in output.text
    assert "Read the PID from the program context" in output.text
    assert output.json_data["raw_log_excerpt"] == "unknown func bpf_get_current_pid_tgid#14"
    assert "tail calls" not in output.text
