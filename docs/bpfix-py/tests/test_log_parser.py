from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

from bpfix.extractor.log_parser import parse_log


def _load_verifier_log(relative_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(relative_path)


def test_parse_log_prefers_specific_rejection_over_source_comment() -> None:
    dynptr = parse_log(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly-cgroup-skb-ingress-61688196.yaml"
        )
    )
    irq = parse_log(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-irq-irq-save-invalid-tc-86a07a3f.yaml"
        )
    )

    assert dynptr.error_line == "the prog does not allow writes to packet data"
    assert dynptr.error_id == "BPFIX-E019"
    assert irq.error_line == "expected uninitialized irq flag as arg#0"
    assert irq.error_id == "BPFIX-E020"


def test_parse_log_prefers_specific_libbpf_reason_over_wrapper_and_summary() -> None:
    func_info = parse_log(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-69192685.yaml")
    )
    kernel_btf = parse_log(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-77462271.yaml")
    )

    assert func_info.error_line == "number of funcs in func_info doesn't match number of subprogs"
    assert func_info.error_id == "BPFIX-E021"
    assert "failed to find kernel BTF type ID" in kernel_btf.error_line
    assert kernel_btf.error_id == "BPFIX-E021"


def test_parse_log_catalog_covers_round2_unknown_taxonomy_patterns() -> None:
    dynptr_slice = parse_log(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-dynptr-slice-var-len1-tc-76a0b3fb.yaml"
        )
    )
    dynptr_const = parse_log(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-dynptr-slice-var-len2-tc-673ab9e7.yaml"
        )
    )
    pkt_end = parse_log(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-60506220.yaml")
    )
    ctx = parse_log(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-67402772.yaml")
    )
    comparison = parse_log(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-71351495.yaml")
    )
    btf_invalid_name = parse_log(
        _load_verifier_log("bpfix-bench/raw/gh/github-aya-rs-aya-1490.yaml")
    )

    assert dynptr_slice.error_id == "BPFIX-E005"
    assert dynptr_const.error_id == "BPFIX-E019"
    assert pkt_end.error_id == "BPFIX-E006"
    assert ctx.error_id == "BPFIX-E023"
    assert comparison.error_id == "BPFIX-E023"
    assert btf_invalid_name.error_id == "BPFIX-E021"


def test_parse_log_prefers_selected_error_line_for_catalog_seed() -> None:
    # clone_invalid1: expected message is "Expected an initialized dynptr as arg #0"
    # which is a source_bug (E012).  Previously the spurious BTF probe line
    # "arg#0 reference type('UNKNOWN') size cannot be determined: -22" was
    # selected instead and mis-mapped to E021 / environment_or_configuration. The fix adds
    # BTF_PROBE_NOISE_RE penalisation so the real dynptr protocol error wins.
    dynptr_unknown = parse_log(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-clone-invalid1-raw-tp-b7206632.yaml"
        )
    )

    assert dynptr_unknown.error_line == "Expected an initialized dynptr as arg #0"
    assert dynptr_unknown.error_id == "BPFIX-E012"
    assert dynptr_unknown.taxonomy_class == "source_bug"
    assert dynptr_unknown.catalog_confidence == "high"


def test_parse_log_does_not_seed_e021_from_btf_probe_preface() -> None:
    data_slice = parse_log(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84.yaml"
        )
    )
    reg_type = parse_log(
        _load_verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-test-dynptr-reg-type-raw-tp-18f079b9.yaml"
        )
    )

    assert data_slice.error_id == "BPFIX-E005"
    assert data_slice.taxonomy_class == "lowering_artifact"
    assert reg_type.error_id == "BPFIX-E019"
    assert reg_type.taxonomy_class == "source_bug"
