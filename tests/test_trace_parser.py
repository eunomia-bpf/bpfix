from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

from bpfix.extractor.trace_parser import (
    BacktrackLine,
    ErrorLine,
    InstructionLine,
    RegisterStateLine,
    SourceAnnotation,
    _is_pointer_type,
    extract_backtrack_chains,
    parse_line,
    parse_trace,
)


def _load_case(relative_path: str) -> dict:
    from bench_fixtures import load_case

    return load_case(relative_path)

def _block(case_path: str, index: int) -> str:
    from bench_fixtures import load_verifier_block

    return load_verifier_block(case_path, index)

def _verifier_log(case_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(case_path)

def _find_line(block: str, needle: str) -> str:
    for line in block.splitlines():
        if needle in line:
            return line
    raise AssertionError(f"line containing {needle!r} not found")


def test_parse_line_classifies_real_verifier_lines() -> None:
    sni_block = _block("bpfix-bench/raw/so/stackoverflow-70750259.yaml", 0)
    packet_block = _block("bpfix-bench/raw/so/stackoverflow-70729664.yaml", 0)

    state_line = parse_line(_find_line(sni_block, "19: R0=pkt(id=0,off=2,r=6,imm=0)"))
    assert isinstance(state_line, RegisterStateLine)
    assert state_line.registers["R0"].type == "pkt"
    assert state_line.registers["R5"].range == 6

    instruction_line = parse_line(_find_line(sni_block, "19: (71) r6 = *(u8 *)(r0 +2)"))
    assert isinstance(instruction_line, InstructionLine)
    assert instruction_line.insn_idx == 19
    assert instruction_line.opcode == "71"
    assert instruction_line.bytecode_text == "r6 = *(u8 *)(r0 +2)"

    source_line = parse_line(_find_line(sni_block, "__u16 ext_len = __bpf_htons(ext->len);"))
    assert isinstance(source_line, SourceAnnotation)
    assert source_line.source_line == "__u16 ext_len = __bpf_htons(ext->len);"

    backtrack_summary = parse_line(_find_line(sni_block, "last_idx 24 first_idx 12"))
    assert isinstance(backtrack_summary, BacktrackLine)
    assert backtrack_summary.last_idx == 24
    assert backtrack_summary.first_idx == 12

    backtrack_detail = parse_line(_find_line(sni_block, "regs=1 stack=0 before 23:"))
    assert isinstance(backtrack_detail, BacktrackLine)
    assert backtrack_detail.regs == "1"
    assert backtrack_detail.stack == "0"
    assert backtrack_detail.before_idx == 23

    error_line = parse_line(_find_line(packet_block, "invalid access to packet, off=26 size=1"))
    assert isinstance(error_line, ErrorLine)
    assert "R7(id=68,off=26,r=0)" in error_line.error_text


def test_parse_trace_groups_real_instruction_blocks() -> None:
    parsed = parse_trace(
        _block("bpfix-bench/raw/so/stackoverflow-70750259.yaml", 0)
    )

    assert parsed.total_instructions == 6
    assert parsed.has_btf_annotations is True
    assert parsed.has_backtracking is True
    assert len(parsed.backtrack_chains) == 1
    assert parsed.error_line == "math between pkt pointer and register with unbounded min value is not allowed"

    first = parsed.instructions[0]
    assert first.insn_idx == 19
    assert first.source_line == "__u16 ext_len = __bpf_htons(ext->len);"
    assert first.pre_state["R0"].type == "pkt"
    assert first.pre_state["R0"].off == 2

    last = parsed.instructions[-1]
    assert last.insn_idx == 24
    assert last.source_line == "if (data_end < (data + ext_len)) {"
    assert last.backtrack is not None
    assert last.backtrack.last_idx == 24
    assert last.backtrack.first_idx == 12
    assert last.is_error is True
    assert parsed.backtrack_chains[0].error_insn == 24
    assert parsed.backtrack_chains[0].first_insn == 12


def test_extract_backtrack_chains_handles_cross_state_sequences() -> None:
    chains = extract_backtrack_chains(
        _block("bpfix-bench/raw/so/stackoverflow-70750259.yaml", 1)
    )

    assert [chain.error_insn for chain in chains] == [39, 35]
    assert [chain.first_insn for chain in chains] == [36, 28]
    assert chains[0].links[0].insn_idx == 38
    assert chains[0].links[-1].insn_idx == 36
    assert chains[1].links[0].bytecode == "(c7) r3 s>>= 32"
    assert chains[1].links[-1].insn_idx == 30


def test_detects_critical_transitions_from_real_logs() -> None:
    bounds_case = parse_trace(
        _block("bpfix-bench/raw/so/stackoverflow-70750259.yaml", 0)
    )
    downgrade_case = parse_trace(
        _block("bpfix-bench/raw/so/stackoverflow-78958420.yaml", 0)
    )

    assert any(
        transition.transition_type == "BOUNDS_COLLAPSE"
        and transition.insn_idx == 22
        and transition.register == "R0"
        for transition in bounds_case.critical_transitions
    )

    assert any(
        transition.transition_type == "TYPE_DOWNGRADE"
        and transition.insn_idx == 73
        and transition.register == "R1"
        and transition.before.type == "pkt"
        and transition.after.type == "scalar"
        for transition in downgrade_case.critical_transitions
    )


def test_extracts_causal_chain_from_real_packet_error() -> None:
    parsed = parse_trace(
        _block("bpfix-bench/raw/so/stackoverflow-78958420.yaml", 0)
    )

    assert parsed.causal_chain is not None
    assert parsed.causal_chain.error_insn == 83
    assert parsed.causal_chain.error_register == "R2"
    assert parsed.causal_chain.chain[-1].role == "error_site"
    assert parsed.causal_chain.chain[-1].insn_idx == 83
    assert any(
        link.insn_idx == 78 and link.register == "R2"
        for link in parsed.causal_chain.chain
    )


def test_full_pipeline_handles_backtracking_packet_case() -> None:
    parsed = parse_trace(
        _block("bpfix-bench/raw/so/stackoverflow-70729664.yaml", 0)
    )

    assert parsed.total_instructions == 12
    assert parsed.has_btf_annotations is True
    assert parsed.has_backtracking is True
    assert parsed.error_line == "invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0)"
    assert any(
        transition.transition_type == "RANGE_LOSS"
        and transition.insn_idx == 2940
        and transition.register == "R7"
        for transition in parsed.critical_transitions
    )
    assert parsed.causal_chain is not None
    assert parsed.causal_chain.chain[0].insn_idx == 2940


def test_parse_trace_keeps_btf_annotations_across_multi_instruction_statement() -> None:
    parsed = parse_trace(
        _verifier_log(
            "bpfix-bench/raw/kernel_selftests/"
            "kernel-selftest-dynptr-fail-skb-invalid-ctx-fentry-fentry-skb-tx-error-17cea403.yaml"
        )
    )

    call_instruction = next(
        instruction for instruction in parsed.instructions if instruction.insn_idx == 4
    )
    assert call_instruction.source_line == "bpf_dynptr_from_skb(skb, 0, &ptr); @ dynptr_fail.c:1265"


def test_parse_trace_recovers_loader_prefixed_instruction_snippet() -> None:
    parsed = parse_trace(
        _verifier_log("bpfix-bench/raw/so/stackoverflow-77568308.yaml")
    )

    assert parsed.total_instructions == 1
    assert parsed.error_line == "R1 invalid mem access 'scalar' (16 line(s) omitted)"
    instruction = parsed.instructions[0]
    assert instruction.insn_idx == 9
    assert instruction.bytecode == "r3 = *(u64 *)(r1 +96)"
    assert instruction.is_error is True
    assert instruction.error_text == "R1 invalid mem access 'scalar' (16 line(s) omitted)"


def test_parse_trace_recovers_colon_prefixed_instructions() -> None:
    parsed = parse_trace(
        _verifier_log("bpfix-bench/raw/so/stackoverflow-77713434.yaml")
    )

    assert parsed.total_instructions == 11
    assert parsed.error_line == "invalid access to map value, value_size=70 off=0 size=16383"
    assert parsed.instructions[0].insn_idx == 599
    assert parsed.instructions[0].source_line is not None
    assert "overrided_bytes" in parsed.instructions[0].source_line
    assert parsed.instructions[-1].insn_idx == 609
    assert parsed.instructions[-1].is_error is True



def test_pointer_family_recognizes_typed_verifier_pointers() -> None:
    assert _is_pointer_type("ptr_sock") is True
    assert _is_pointer_type("trusted_ptr_task_struct") is True
    assert _is_pointer_type("rcu_ptr_task_struct") is True
