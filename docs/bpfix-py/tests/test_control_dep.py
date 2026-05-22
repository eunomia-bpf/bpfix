"""Tests for bpfix/extractor/engine/control_dep.py.

Tests use synthetic TracedInstruction / TraceCFG objects to exercise the
control dependence analysis without needing a real verifier log.

Test patterns:
  1. Linear trace → no control dependence.
  2. Diamond (if-then-else) → then/else blocks depend on the if.
  3. Loop → body depends on the loop-condition branch.
  4. Disconnected / trivial CFG edge cases.
  5. Real case: stackoverflow-70750259 (integration smoke test).
"""

from __future__ import annotations

from pathlib import Path

import yaml
import pytest

ROOT = Path(__file__).resolve().parents[1]

from bpfix.extractor.trace_parser import TracedInstruction
from bpfix.extractor.engine.cfg_builder import build_cfg, TraceCFG
from bpfix.extractor.engine.control_dep import (
    ControlDep,
    compute_control_dependence,
    compute_control_dependence_from_trace,
    controlling_branches,
    control_dependent_instructions,
)


# ---------------------------------------------------------------------------
# Helper factories (mirrors test_cfg_builder.py)
# ---------------------------------------------------------------------------


def _insn(
    idx: int,
    bytecode: str,
    opcode_hex: str | None = None,
) -> TracedInstruction:
    return TracedInstruction(
        insn_idx=idx,
        bytecode=bytecode,
        source_line=None,
        pre_state={},
        post_state={},
        backtrack=None,
        is_error=False,
        error_text=None,
        opcode_hex=opcode_hex,
    )


def _build(insns: list) -> tuple[TraceCFG, ControlDep]:
    """Build CFG and compute control dependence in one call."""
    cfg = build_cfg(insns)
    cd = compute_control_dependence(cfg)
    return cfg, cd


# ---------------------------------------------------------------------------
# Test 1: Linear trace — no control dependence
# ---------------------------------------------------------------------------


def test_linear_trace_no_control_dependence() -> None:
    """A purely sequential trace has no control dependence."""
    insns = [
        _insn(0, "r1 = 1", opcode_hex="b7"),
        _insn(1, "r0 = r1", opcode_hex="bf"),
        _insn(2, "r0 += 2", opcode_hex="07"),
        _insn(3, "exit", opcode_hex="95"),
    ]
    _, cd = _build(insns)

    # No instruction should have any controlling branch.
    for idx in range(4):
        assert controlling_branches(cd, idx) == set(), (
            f"insn {idx} unexpectedly control-dependent: {cd.deps.get(idx)}"
        )


# ---------------------------------------------------------------------------
# Test 2: Diamond pattern (if-then-else merge)
# ---------------------------------------------------------------------------
#
#  0: r0 = 1          (entry)
#  1: if r0 > r2 goto pc+2   (conditional branch: fall→2, target→4)
#  2: r1 = 10         (then-branch)
#  3: goto pc+1       (jump to merge at 5)
#  4: r1 = 20         (else-branch)
#  5: r0 = r1         (merge)
#  6: exit


def test_diamond_pattern_control_dependence() -> None:
    """In a diamond, the then/else blocks are control-dependent on the branch."""
    insns = [
        _insn(0, "r0 = 1", opcode_hex="b7"),
        # Conditional: fall-through=2, target=4 (pc+2 means idx+2+1=4)
        _insn(1, "if r0 > r2 goto pc+2", opcode_hex="2d"),
        # Then branch (fall-through path)
        _insn(2, "r1 = 10", opcode_hex="b7"),
        # Jump to merge point (goto pc+1 → 3+1+1 = 5)
        _insn(3, "goto pc+1", opcode_hex="05"),
        # Else branch (branch-taken path)
        _insn(4, "r1 = 20", opcode_hex="b7"),
        # Merge point
        _insn(5, "r0 = r1", opcode_hex="bf"),
        _insn(6, "exit", opcode_hex="95"),
    ]
    cfg, cd = _build(insns)

    # Verify CFG structure first.
    # insn 1 must have successors {2, 4}.
    assert cfg.insn_successors.get(1) == {2, 4}, (
        f"Expected {{2,4}}, got {cfg.insn_successors.get(1)}"
    )

    # Then-branch (insn 2) must be control-dependent on the branch (insn 1).
    assert 1 in controlling_branches(cd, 2), (
        f"insn 2 should depend on branch at insn 1; deps={cd.deps.get(2)}"
    )

    # Else-branch (insn 4) must be control-dependent on the branch (insn 1).
    assert 1 in controlling_branches(cd, 4), (
        f"insn 4 should depend on branch at insn 1; deps={cd.deps.get(4)}"
    )

    # The merge point (insn 5) post-dominates insn 1, so it should NOT be
    # control-dependent on insn 1.
    # (insn 5 is reachable on BOTH paths, so it is NOT dependent on the branch)
    # Note: insn 3 (goto) is on the then-path only, so it IS control-dependent.
    assert 1 in controlling_branches(cd, 3), (
        f"insn 3 (goto) should depend on branch at insn 1; deps={cd.deps.get(3)}"
    )

    # Inverse query: insns control-dependent on branch 1.
    cd_on_1 = control_dependent_instructions(cd, 1)
    assert 2 in cd_on_1
    assert 4 in cd_on_1
    assert 3 in cd_on_1  # goto is also on one path only


# ---------------------------------------------------------------------------
# Test 3: Loop — body is control-dependent on loop condition
# ---------------------------------------------------------------------------
#
#  0: r3 = 0          (loop init)
#  1: r3 += 1         (loop body start / header)
#  2: r4 = r3
#  3: if r3 s>= r1 goto pc+1   (fall→4 (body cont.), target→5 (exit))
#  4: goto pc-4       (back edge to 1)
#  5: exit


def test_loop_body_control_dependent_on_condition() -> None:
    """Loop body instructions are control-dependent on the loop-condition branch."""
    insns = [
        _insn(0, "r3 = 0", opcode_hex="b7"),
        # Loop header / body
        _insn(1, "r3 += 1", opcode_hex="07"),
        _insn(2, "r4 = r3", opcode_hex="bf"),
        # Loop condition: fall-through=4 (continue), target=5 (exit loop)
        _insn(3, "if r3 s>= r1 goto pc+1", opcode_hex="7d"),
        # Back-edge (goto pc-4 → 4+(-4)+1 = 1)
        _insn(4, "goto pc-4", opcode_hex="05"),
        _insn(5, "exit", opcode_hex="95"),
    ]
    cfg, cd = _build(insns)

    # Verify CFG: insn 3 has successors {4, 5}.
    assert cfg.insn_successors.get(3) == {4, 5}, (
        f"Expected {{4,5}}, got {cfg.insn_successors.get(3)}"
    )
    # Back edge: insn 4 → 1.
    assert 1 in cfg.insn_successors.get(4, set()), (
        f"Back edge 4→1 missing; {cfg.insn_successors.get(4)}"
    )

    # insn 4 (the back-edge goto) is on the loop-body path → control-dependent on 3.
    assert 3 in controlling_branches(cd, 4), (
        f"insn 4 should depend on loop branch at insn 3; deps={cd.deps.get(4)}"
    )


# ---------------------------------------------------------------------------
# Test 4: Single instruction (edge case)
# ---------------------------------------------------------------------------


def test_single_exit_instruction() -> None:
    """A trace with a single exit instruction has no control dependence."""
    insns = [_insn(0, "exit", opcode_hex="95")]
    _, cd = _build(insns)
    assert controlling_branches(cd, 0) == set()


# ---------------------------------------------------------------------------
# Test 5: Two-branch, no merge point
# ---------------------------------------------------------------------------
#
#  0: if r0 > r1 goto pc+1  (fall→1, target→2)
#  1: exit
#  2: exit


def test_two_exits_both_control_dependent() -> None:
    """Two exit paths are each control-dependent on the branch."""
    insns = [
        _insn(0, "if r0 > r1 goto pc+1", opcode_hex="2d"),
        _insn(1, "exit", opcode_hex="95"),
        _insn(2, "exit", opcode_hex="95"),
    ]
    cfg, cd = _build(insns)

    # insn 0 must have successors {1, 2}.
    assert cfg.insn_successors.get(0) == {1, 2}

    # Both exit paths are control-dependent on insn 0.
    assert 0 in controlling_branches(cd, 1), (
        f"insn 1 should depend on branch at insn 0; deps={cd.deps.get(1)}"
    )
    assert 0 in controlling_branches(cd, 2), (
        f"insn 2 should depend on branch at insn 0; deps={cd.deps.get(2)}"
    )


# ---------------------------------------------------------------------------
# Test 6: Empty CFG
# ---------------------------------------------------------------------------


def test_empty_cfg() -> None:
    """Computing control dependence on an empty CFG returns an empty result."""
    cfg = build_cfg([])
    cd = compute_control_dependence(cfg)
    assert cd.deps == {}
    assert cd.ipdom == {}


# ---------------------------------------------------------------------------
# Test 7: ControlDep.ipdom sanity checks for linear trace
# ---------------------------------------------------------------------------


def test_linear_trace_ipdom() -> None:
    """In a linear trace, each instruction's immediate post-dominator is the
    next instruction (except the exit which post-dominates itself)."""
    insns = [
        _insn(0, "r1 = 1", opcode_hex="b7"),
        _insn(1, "r0 = r1", opcode_hex="bf"),
        _insn(2, "exit", opcode_hex="95"),
    ]
    _, cd = _build(insns)

    # insn 2 is the only exit; it should be its own ipdom (or map to itself).
    assert cd.ipdom.get(2, 2) == 2

    # insn 1 is post-dominated by insn 2 (the exit).
    assert cd.ipdom.get(1) == 2

    # insn 0 is post-dominated by insn 1 (which then leads to 2).
    assert cd.ipdom.get(0) == 1


# ---------------------------------------------------------------------------
# Test 8: Diamond — post-dominator of branch is the merge point
# ---------------------------------------------------------------------------


def test_diamond_ipdom() -> None:
    """In a diamond, the branch's immediate post-dominator is the merge point."""
    #
    #  0: if r0 > 0 goto pc+1   (fall→1, target→2)
    #  1: r1 = 0                 (then)
    #  2: r1 = 1                 (else / merge — both paths reach here)
    #  3: exit
    #
    # NOTE: insn 2 is the merge only if both paths reach it.
    # Path A (fall):  0 → 1 → ??? (1 has no explicit successor to 2)
    # To make a proper diamond we need an explicit goto from 1 to 2:
    #  1: goto pc+0  (i.e., target = 1+0+1 = 2)
    insns = [
        _insn(0, "if r0 > 0 goto pc+1", opcode_hex="2d"),  # fall→1, target→2
        _insn(1, "goto pc+0", opcode_hex="05"),             # unconditional → 2
        _insn(2, "r1 = 1", opcode_hex="b7"),                # merge
        _insn(3, "exit", opcode_hex="95"),
    ]
    cfg, cd = _build(insns)

    # insn 0 → successors {1, 2}
    assert cfg.insn_successors.get(0) == {1, 2}, (
        f"Expected {{1,2}}, got {cfg.insn_successors.get(0)}"
    )

    # merge point (2) post-dominates branch (0): ipdom[0] should be 2.
    assert cd.ipdom.get(0) == 2, (
        f"Expected ipdom[0]=2 (merge), got {cd.ipdom.get(0)}"
    )

    # insn 1 is control-dependent on insn 0 (it's only on the fall-through path).
    assert 0 in controlling_branches(cd, 1), (
        f"insn 1 should depend on branch at 0; deps={cd.deps.get(1)}"
    )

    # insn 2 (merge) should NOT be control-dependent on insn 0
    # (it is post-dominated by itself — it's the join node).
    # The merge is reachable from BOTH successors, so it does not depend on 0.
    assert 0 not in controlling_branches(cd, 2), (
        f"merge insn 2 should NOT depend on branch at 0; deps={cd.deps.get(2)}"
    )


# ---------------------------------------------------------------------------
# Test 9: Integration — real case (stackoverflow-70750259)
# ---------------------------------------------------------------------------


def _load_case(relative_path: str) -> dict:
    from bench_fixtures import load_case

    return load_case(relative_path)

def _verifier_log(case_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(case_path)


def test_real_case_smoke() -> None:
    """Smoke test: run control dependence on the stackoverflow-70750259 case.

    Verifies that:
    - compute_control_dependence returns without error.
    - The error instruction (insn 39, r5 += r0) has at least one controlling
      branch (from the design doc: insns 28 and 36 are expected).
    - All instruction indices in ipdom are actual instruction indices (no
      spurious virtual nodes in the public result).
    """
    case_path = "bpfix-bench/raw/so/stackoverflow-70750259.yaml"
    try:
        log = _verifier_log(case_path)
    except FileNotFoundError:
        pytest.skip(f"Case file not found: {case_path}")

    from bpfix.extractor.trace_parser import parse_trace

    parsed = parse_trace(log)
    # Use the high-level entry point that provides insn_map for opcode-based
    # detection of conditional branches in partial CFGs.
    cd = compute_control_dependence_from_trace(parsed)

    # The error instruction should exist in the trace.
    insn_idxs = {i.insn_idx for i in parsed.instructions}
    if 39 not in insn_idxs:
        pytest.skip("Instruction 39 not found in parsed trace")

    # insn 39 should have at least one controlling branch.
    branches = controlling_branches(cd, 39)
    assert len(branches) >= 1, (
        f"Expected at least one controlling branch for insn 39, got {branches}"
    )

    # ipdom should contain only real instruction indices (no _VIRT_EXIT = -1).
    for node, pd in cd.ipdom.items():
        assert node >= 0, f"Virtual node {node} in ipdom keys"
        assert pd >= 0, f"Virtual node {pd} in ipdom values (for key {node})"

    # All instructions that appear in the trace should be in ipdom.
    for idx in insn_idxs:
        assert idx in cd.ipdom, f"insn {idx} missing from ipdom"
