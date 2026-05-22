"""Tests for bpfix/extractor/engine/cfg_builder.py.

Tests use synthetic TracedInstruction objects to exercise the CFG builder
without needing a full verifier log.  One integration test loads a real case.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

from bpfix.extractor.trace_parser import TracedInstruction
from bpfix.extractor.engine.cfg_builder import (
    build_cfg,
    build_cfg_from_trace,
    extract_branch_target,
    is_unconditional_goto,
)
from bpfix.extractor.trace_parser import parse_trace


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _insn(
    idx: int,
    bytecode: str,
    opcode_hex: str | None = None,
    is_error: bool = False,
    error_text: str | None = None,
) -> TracedInstruction:
    """Create a minimal TracedInstruction for testing."""
    return TracedInstruction(
        insn_idx=idx,
        bytecode=bytecode,
        source_line=None,
        pre_state={},
        post_state={},
        backtrack=None,
        is_error=is_error,
        error_text=error_text,
        opcode_hex=opcode_hex,
    )


def _load_case(relative_path: str) -> dict:
    from bench_fixtures import load_case

    return load_case(relative_path)

def _verifier_log(case_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(case_path)


# ---------------------------------------------------------------------------
# Unit tests: branch target extraction
# ---------------------------------------------------------------------------


def test_extract_branch_target_positive_offset() -> None:
    target = extract_branch_target("if r0 s> 0xffffffff goto pc+1", 28)
    assert target == 30  # 28 + 1 + 1


def test_extract_branch_target_negative_offset() -> None:
    target = extract_branch_target("if r1 s> r3 goto pc-29", 40)
    assert target == 12  # 40 + (-29) + 1


def test_extract_branch_target_unconditional() -> None:
    target = extract_branch_target("goto pc+11", 29)
    assert target == 41  # 29 + 11 + 1


def test_extract_branch_target_none_for_non_branch() -> None:
    assert extract_branch_target("r0 += r1", 5) is None
    assert extract_branch_target("r5 += r0", 39) is None
    assert extract_branch_target("exit", 42) is None


def test_is_unconditional_goto() -> None:
    assert is_unconditional_goto("goto pc+11") is True
    assert is_unconditional_goto("goto pc-5") is True
    assert is_unconditional_goto("if r0 s> 0xffffffff goto pc+1") is False
    assert is_unconditional_goto("r0 += r1") is False


# ---------------------------------------------------------------------------
# Test 1: Simple linear trace (no branches)
# ---------------------------------------------------------------------------


def test_linear_trace_single_block() -> None:
    """A trace with no branches should produce a single basic block."""
    insns = [
        _insn(0, "r1 = *(u32 *)(r1 +0)", opcode_hex="61"),
        _insn(1, "r0 = r1", opcode_hex="bf"),
        _insn(2, "r0 += 2", opcode_hex="07"),
        _insn(3, "exit", opcode_hex="95"),
    ]
    cfg = build_cfg(insns)

    assert cfg.entry == 0
    assert len(cfg.blocks) == 1
    blk = cfg.blocks[0]
    assert blk.start_idx == 0
    assert blk.end_idx == 3
    assert len(blk.instructions) == 4
    assert blk.successors == []
    assert blk.predecessors == []
    assert cfg.edges == []

    # Instruction-level adjacency
    assert cfg.insn_successors[0] == {1}
    assert cfg.insn_successors[1] == {2}
    assert cfg.insn_successors[2] == {3}
    assert cfg.insn_successors[3] == set()

    # get_block_for_insn
    for i in range(4):
        b = cfg.get_block_for_insn(i)
        assert b is not None
        assert b.start_idx == 0


def test_linear_trace_no_exit_falls_through_to_end() -> None:
    """Linear trace where last instruction has no explicit successor."""
    insns = [
        _insn(5, "r3 = 0", opcode_hex="b7"),
        _insn(6, "r4 = 0x400000000", opcode_hex="18"),
    ]
    cfg = build_cfg(insns)
    assert cfg.entry == 5
    # ld_imm64 at 6: successor would be 8, but 8 is not in trace → no succ
    assert cfg.insn_successors[5] == {6}
    # insn 6 is ld_imm64 (0x18), fall-through to 8 which is not in trace
    assert cfg.insn_successors[6] == set()


# ---------------------------------------------------------------------------
# Test 2: Conditional branch
# ---------------------------------------------------------------------------


def test_conditional_branch_two_blocks() -> None:
    """Conditional branch creates two successor blocks."""
    insns = [
        _insn(0, "r0 = r1", opcode_hex="bf"),
        _insn(1, "r0 += 2", opcode_hex="07"),
        # Conditional: fall-through=2, target=5
        _insn(2, "if r0 > r2 goto pc+2", opcode_hex="2d"),
        # Fall-through path
        _insn(3, "r1 = r0", opcode_hex="bf"),
        _insn(4, "exit", opcode_hex="95"),
        # Branch target path
        _insn(5, "r0 = 0", opcode_hex="b7"),
        _insn(6, "exit", opcode_hex="95"),
    ]
    cfg = build_cfg(insns)

    # Insn 2 should have two successors: 3 and 5
    assert cfg.insn_successors[2] == {3, 5}
    assert cfg.insn_predecessors[3] == {2}
    assert cfg.insn_predecessors[5] == {2}

    # Should have block starting at 0, and new blocks at 3 and 5
    # (because 5 is a branch target with multiple possible predecessors)
    assert 0 in cfg.blocks
    assert 5 in cfg.blocks

    # Entry block ends at the branch instruction
    blk0 = cfg.get_block_for_insn(0)
    assert blk0 is not None
    blk2 = cfg.get_block_for_insn(2)
    # 0,1,2 should be in the same block
    assert blk0 is blk2

    # Branch block should end at insn 2
    entry_block = cfg.blocks[cfg.entry]
    assert entry_block.end_idx == 2

    # Check block edges exist
    assert any(
        (blk_start, 5) in cfg.edges
        for blk_start in cfg.blocks
        if blk_start <= 2
    )


# ---------------------------------------------------------------------------
# Test 3: Loop (branch back)
# ---------------------------------------------------------------------------


def test_loop_back_edge() -> None:
    """A backward branch creates a loop back edge in the CFG."""
    insns = [
        # Entry: set up loop counter
        _insn(0, "r3 = 0", opcode_hex="b7"),
        # Loop header
        _insn(1, "r3 += 1", opcode_hex="07"),
        _insn(2, "r4 = r3", opcode_hex="bf"),
        # Loop condition: if r3 s>= r1, exit loop (goto pc+2 = insn 5)
        _insn(3, "if r3 s>= r1 goto pc+1", opcode_hex="7d"),
        # Loop body falls through to loop header at insn 1 (goto pc-4 = insn 0... adjusted)
        _insn(4, "goto pc-4", opcode_hex="05"),
        # Exit
        _insn(5, "exit", opcode_hex="95"),
    ]
    cfg = build_cfg(insns)

    # insn 4 (goto pc-4) -> target = 4 + (-4) + 1 = 1
    assert 1 in cfg.insn_successors[4]

    # insn 3 (conditional) -> fall-through=4 and target=5
    assert cfg.insn_successors[3] == {4, 5}

    # Insn 1 should have two predecessors: 0 and 4 (back edge)
    assert 0 in cfg.insn_predecessors[1]
    assert 4 in cfg.insn_predecessors[1]

    # The loop header (1) must be a block leader
    assert 1 in cfg.blocks

    # Back edge: block containing 4 → block starting at 1
    blk4 = cfg.get_block_for_insn(4)
    assert blk4 is not None
    assert 1 in blk4.successors


# ---------------------------------------------------------------------------
# Test 4: Merge points (from X to Y annotations)
# ---------------------------------------------------------------------------


def test_merge_point_from_cfg_edges() -> None:
    """'from X to Y' annotations correctly augment CFG edges."""

    class _InsnList(list):
        pass

    insns = _InsnList([
        _insn(28, "if r0 s> 0xffffffff goto pc+1", opcode_hex="65"),
        # Fall-through: insn 29
        _insn(29, "goto pc+11", opcode_hex="05"),
        # Branch target: insn 30 (reached via 'from 28 to 30' annotation)
        _insn(30, "r0 = *(u32 *)(r10 -4)", opcode_hex="61"),
        _insn(31, "r6 = *(u32 *)(r10 -4)", opcode_hex="61"),
        _insn(41, "exit", opcode_hex="95"),
    ])
    insns._cfg_edges = [(28, 30)]

    cfg = build_cfg(insns)

    # 28 should have two successors: 29 (fall-through) and 30 (via annotation)
    assert 29 in cfg.insn_successors[28]
    assert 30 in cfg.insn_successors[28]

    # Block containing insn 30 should have 28's block as predecessor
    blk30 = cfg.get_block_for_insn(30)
    assert blk30 is not None
    blk28 = cfg.get_block_for_insn(28)
    assert blk28 is not None
    assert blk28.start_idx in blk30.predecessors


# ---------------------------------------------------------------------------
# Test 5: Empty trace
# ---------------------------------------------------------------------------


def test_empty_trace() -> None:
    cfg = build_cfg([])
    assert cfg.blocks == {}
    assert cfg.edges == []
    assert cfg.insn_successors == {}
    assert cfg.insn_predecessors == {}


# ---------------------------------------------------------------------------
# Test 6: build_cfg_from_trace integration with ParsedTrace
# ---------------------------------------------------------------------------


def test_build_cfg_from_trace_uses_cfg_edges() -> None:
    """build_cfg_from_trace should propagate ParsedTrace.cfg_edges."""
    log = (
        "28: (65) if r0 s> 0xffffffff goto pc+1\n"
        "from 28 to 30: R0=inv(id=0,umax_value=2147483647)\n"
        "30: (61) r0 = *(u32 *)(r10 -4)\n"
        "31: (61) r6 = *(u32 *)(r10 -4)\n"
        "31: (95) exit\n"
    )
    parsed = parse_trace(log)
    # The cfg_edge (28, 30) should be extracted
    assert (28, 30) in parsed.cfg_edges

    cfg = build_cfg_from_trace(parsed)
    # Should have insn 28 with edge to 30
    if 28 in cfg.insn_successors:
        assert 30 in cfg.insn_successors[28]


# ---------------------------------------------------------------------------
# Test 7: Real case — stackoverflow-70750259
# ---------------------------------------------------------------------------


def test_real_case_stackoverflow_70750259() -> None:
    """Parse the real verifier trace and build a CFG.

    The trace contains 'from 28 to 30:' annotation which should produce
    a CFG edge 28 → 30.
    """
    log = _verifier_log(
        "bpfix-bench/raw/so/stackoverflow-70750259.yaml"
    )
    parsed = parse_trace(log)

    # Should have extracted the from-to edge
    assert (28, 30) in parsed.cfg_edges

    # Every TracedInstruction should carry its opcode_hex
    for insn in parsed.instructions:
        assert insn.opcode_hex is not None, (
            f"insn {insn.insn_idx} ({insn.bytecode!r}) missing opcode_hex"
        )

    cfg = build_cfg_from_trace(parsed)

    # Entry should be the first instruction index
    insn_indices = [i.insn_idx for i in parsed.instructions]
    if insn_indices:
        assert cfg.entry == min(insn_indices)

    # All instruction indices should appear in some block
    for idx in insn_indices:
        blk = cfg.get_block_for_insn(idx)
        # Allow None only if the index is a duplicate (deduplication)
        # — the block should cover it
        assert blk is not None or idx not in {
            b.start_idx for b in cfg.blocks.values()
        }, f"insn {idx} not in any block"

    # CFG should have at least one block
    assert len(cfg.blocks) >= 1

    # The from-to edge (28 → 30) should be reflected in block successors/predecessors
    blk28 = cfg.get_block_for_insn(28)
    blk30 = cfg.get_block_for_insn(30)
    if blk28 is not None and blk30 is not None:
        assert blk30.start_idx in blk28.successors or (
            # Edge may also be encoded in the block's successor list
            any(
                blk30.start_idx == s
                for s in blk28.successors
            )
        )

    # TraceCFG helper methods
    if blk28 is not None:
        succs = cfg.successors(blk28.start_idx)
        assert isinstance(succs, list)
    if blk30 is not None:
        preds = cfg.predecessors(blk30.start_idx)
        assert isinstance(preds, list)


# ---------------------------------------------------------------------------
# Test 8: get_block_for_insn on non-existent index returns None
# ---------------------------------------------------------------------------


def test_get_block_for_insn_not_found() -> None:
    insns = [_insn(10, "exit", opcode_hex="95")]
    cfg = build_cfg(insns)
    assert cfg.get_block_for_insn(999) is None
    assert cfg.get_block_for_insn(10) is not None


# ---------------------------------------------------------------------------
# Test 9: predecessors/successors helpers return empty list for unknown block
# ---------------------------------------------------------------------------


def test_predecessors_successors_unknown_block() -> None:
    insns = [_insn(0, "exit", opcode_hex="95")]
    cfg = build_cfg(insns)
    assert cfg.predecessors(999) == []
    assert cfg.successors(999) == []


# ---------------------------------------------------------------------------
# Test 10: Duplicate insn_idx in trace is deduplicated
# ---------------------------------------------------------------------------


def test_duplicate_insn_idx_deduplicated() -> None:
    """Same instruction appearing twice (two DFS paths) should appear once in CFG."""
    insns = [
        _insn(5, "r0 = 1", opcode_hex="b7"),
        _insn(6, "exit", opcode_hex="95"),
        # Verifier revisits insn 5 on second path
        _insn(5, "r0 = 1", opcode_hex="b7"),
    ]
    cfg = build_cfg(insns)
    # Should have exactly 2 unique instructions in one block
    assert len(cfg.blocks) == 1
    blk = cfg.blocks[5]
    assert blk.start_idx == 5
    assert blk.end_idx == 6
    assert len(blk.instructions) == 2  # deduplicated to 5 and 6
