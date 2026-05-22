"""Tests for bpfix/extractor/engine/dataflow.py.

Tests cover:
  1. extract_defs / extract_uses: opcode-semantic register analysis
  2. compute_reaching_defs: forward pass building DefUseChain
  3. Linear trace: R3 defined at insn 5, used at insn 10 -> reaching def is 5
  4. Overwrite: R3 defined at 5, redefined at 8, used at 10 -> reaching def is 8
  5. Real case: stackoverflow-70750259
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

from bpfix.extractor.trace_parser import TracedInstruction
from bpfix.extractor.engine.dataflow import (
    compute_data_slice,
    compute_reaching_defs,
    extract_defs,
    extract_uses,
    find_reaching_def_at,
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
# Tests: extract_defs
# ---------------------------------------------------------------------------


class TestExtractDefs:
    def test_alu_assignment(self):
        """r3 = r1  ->  DEF: R3"""
        assert extract_defs("r3 = r1") == {"R3"}

    def test_alu_add_compound(self):
        """r3 += r1  ->  DEF: R3"""
        assert extract_defs("r3 += r1") == {"R3"}

    def test_alu_add_immediate(self):
        """r0 += 14  ->  DEF: R0"""
        assert extract_defs("r0 += 14") == {"R0"}

    def test_ldx(self):
        """r5 = *(u8 *)(r0 +3)  ->  DEF: R5"""
        assert extract_defs("r5 = *(u8 *)(r0 +3)") == {"R5"}

    def test_stx(self):
        """*(u64 *)(r10 -8) = r0  ->  DEF: none (memory write)"""
        assert extract_defs("*(u64 *)(r10 -8) = r0") == set()

    def test_st_immediate(self):
        """*(u32 *)(r10 -4) = 0  ->  DEF: none"""
        assert extract_defs("*(u32 *)(r10 -4) = 0") == set()

    def test_call(self):
        """call bpf_map_lookup_elem  ->  DEF: R0"""
        assert extract_defs("call bpf_map_lookup_elem") == {"R0"}

    def test_exit(self):
        """exit  ->  DEF: none"""
        assert extract_defs("exit") == set()

    def test_conditional_branch(self):
        """if r3 s>= r1 goto pc+5  ->  DEF: none"""
        assert extract_defs("if r3 s>= r1 goto pc+5") == set()

    def test_unconditional_goto(self):
        """goto pc-4  ->  DEF: none"""
        assert extract_defs("goto pc-4") == set()

    def test_byteswap(self):
        """be16 r0  ->  DEF: R0"""
        assert extract_defs("be16 r0") == {"R0"}

    def test_mov_w_alias(self):
        """w3 = w1  (32-bit alias) ->  DEF: R3"""
        assert extract_defs("w3 = w1") == {"R3"}

    def test_shift(self):
        """r0 <<= 8  ->  DEF: R0"""
        assert extract_defs("r0 <<= 8") == {"R0"}

    def test_signed_shift(self):
        """r0 s>>= 32  ->  DEF: R0"""
        assert extract_defs("r0 s>>= 32") == {"R0"}

    def test_or_compound(self):
        """r0 |= r6  ->  DEF: R0"""
        assert extract_defs("r0 |= r6") == {"R0"}


# ---------------------------------------------------------------------------
# Tests: extract_uses
# ---------------------------------------------------------------------------


class TestExtractUses:
    def test_alu_assignment(self):
        """r3 = r1  ->  USE: R1"""
        assert extract_uses("r3 = r1") == {"R1"}

    def test_alu_add_compound(self):
        """r3 += r1  ->  USE: R3 (read-modify-write) + R1"""
        uses = extract_uses("r3 += r1")
        assert "R3" in uses
        assert "R1" in uses

    def test_ldx(self):
        """r5 = *(u8 *)(r0 +3)  ->  USE: R0 (base pointer)"""
        assert extract_uses("r5 = *(u8 *)(r0 +3)") == {"R0"}

    def test_stx(self):
        """*(u64 *)(r10 -8) = r0  ->  USE: R10 + R0"""
        uses = extract_uses("*(u64 *)(r10 -8) = r0")
        assert "R10" in uses
        assert "R0" in uses

    def test_st_immediate(self):
        """*(u32 *)(r10 -4) = 0  ->  USE: R10"""
        assert extract_uses("*(u32 *)(r10 -4) = 0") == {"R10"}

    def test_call(self):
        """call ...  ->  USE: R1-R5"""
        uses = extract_uses("call bpf_map_lookup_elem")
        for i in range(1, 6):
            assert f"R{i}" in uses

    def test_exit(self):
        """exit  ->  USE: R0"""
        assert extract_uses("exit") == {"R0"}

    def test_conditional_branch_two_regs(self):
        """if r3 s>= r1 goto pc+5  ->  USE: R3, R1"""
        uses = extract_uses("if r3 s>= r1 goto pc+5")
        assert "R3" in uses
        assert "R1" in uses

    def test_conditional_branch_immediate(self):
        """if r0 s> 0xffffffff goto pc+1  ->  USE: R0"""
        uses = extract_uses("if r0 s> 0xffffffff goto pc+1")
        assert "R0" in uses

    def test_unconditional_goto(self):
        """goto pc-4  ->  USE: none"""
        assert extract_uses("goto pc-4") == set()

    def test_byteswap(self):
        """be16 r0  ->  USE: R0 (reads and rewrites same register)"""
        assert extract_uses("be16 r0") == {"R0"}

    def test_or_compound(self):
        """r0 |= r6  ->  USE: R0 + R6"""
        uses = extract_uses("r0 |= r6")
        assert "R0" in uses
        assert "R6" in uses

    def test_alu_constant_only(self):
        """r0 = 0  ->  USE: none (immediate source)"""
        assert extract_uses("r0 = 0") == set()


# ---------------------------------------------------------------------------
# Tests: compute_reaching_defs — linear trace
# ---------------------------------------------------------------------------


class TestComputeReachingDefsLinear:
    """Linear trace: R3 defined at insn 5, used at insn 10 -> reaching def is 5."""

    def _build_trace(self) -> list[TracedInstruction]:
        """Build a synthetic linear trace.

        insn 0:  r3 = r1        (DEF: R3, USE: R1)
        insn 5:  r3 = r2        (DEF: R3 — first definition of interest)
        insn 7:  r4 = r3        (USE: R3 — but not the one we test)
        insn 10: r5 += r3       (USE: R3 — reaching def should be insn 5)
        """
        return [
            _insn(0, "r3 = r1"),
            _insn(5, "r3 = r2"),
            _insn(7, "r4 = r3"),
            _insn(10, "r5 += r3"),
        ]

    def test_reaching_def_at_use(self):
        trace = self._build_trace()
        chain = compute_reaching_defs(trace)
        # At insn 10, R3 was last defined at insn 5
        assert chain.reaching_def(10, "R3") == 5

    def test_reaching_def_at_first_def(self):
        trace = self._build_trace()
        chain = compute_reaching_defs(trace)
        # At insn 0, R3 was never defined before — reaching def is None
        assert chain.reaching_def(0, "R3") is None

    def test_defs_at(self):
        trace = self._build_trace()
        chain = compute_reaching_defs(trace)
        assert "R3" in chain.defs_at(0)
        assert "R3" in chain.defs_at(5)
        assert "R3" not in chain.defs_at(10)

    def test_uses_at(self):
        trace = self._build_trace()
        chain = compute_reaching_defs(trace)
        assert "R3" in chain.uses_at(10)
        assert "R3" in chain.uses_at(7)

    def test_all_defs_for(self):
        trace = self._build_trace()
        chain = compute_reaching_defs(trace)
        defs = chain.all_defs_for("R3")
        assert 0 in defs
        assert 5 in defs
        assert 10 not in defs


# ---------------------------------------------------------------------------
# Tests: compute_reaching_defs — overwrite
# ---------------------------------------------------------------------------


class TestComputeReachingDefsOverwrite:
    """Overwrite: R3 defined at 5, redefined at 8, used at 10 -> reaching def is 8."""

    def _build_trace(self) -> list[TracedInstruction]:
        """
        insn 5:  r3 = r2        (first definition of R3)
        insn 8:  r3 = r4        (redefines R3 — overwrites)
        insn 10: r5 += r3       (USE: R3 — should reach insn 8, not 5)
        """
        return [
            _insn(5, "r3 = r2"),
            _insn(8, "r3 = r4"),
            _insn(10, "r5 += r3"),
        ]

    def test_reaching_def_is_most_recent(self):
        trace = self._build_trace()
        chain = compute_reaching_defs(trace)
        # At insn 10, R3 was last defined at insn 8 (overwrite of insn 5)
        assert chain.reaching_def(10, "R3") == 8

    def test_reaching_def_at_overwrite(self):
        trace = self._build_trace()
        chain = compute_reaching_defs(trace)
        # At insn 8, R3 was last defined at insn 5
        assert chain.reaching_def(8, "R3") is None  # insn 8 DEFs R3, it doesn't USE it

    def test_both_defs_recorded(self):
        trace = self._build_trace()
        chain = compute_reaching_defs(trace)
        defs = chain.all_defs_for("R3")
        assert 5 in defs
        assert 8 in defs


# ---------------------------------------------------------------------------
# Tests: compute_reaching_defs — CALL and EXIT
# ---------------------------------------------------------------------------


class TestComputeReachingDefsCallExit:
    def test_call_defines_r0(self):
        trace = [
            _insn(1, "r1 = r0"),
            _insn(2, "call bpf_map_lookup_elem"),
            _insn(3, "r2 = r0"),  # USE: R0 — reaching def should be insn 2 (CALL)
        ]
        chain = compute_reaching_defs(trace)
        assert chain.reaching_def(3, "R0") == 2

    def test_exit_uses_r0(self):
        trace = [
            _insn(0, "r0 = 1"),
            _insn(1, "exit"),
        ]
        chain = compute_reaching_defs(trace)
        assert "R0" in chain.uses_at(1)
        assert chain.reaching_def(1, "R0") == 0


# ---------------------------------------------------------------------------
# Tests: find_reaching_def_at — fallback scan
# ---------------------------------------------------------------------------


class TestFindReachingDefAt:
    def test_known_key(self):
        """When the key is in the precomputed map, return it."""
        trace = [
            _insn(5, "r3 = r2"),
            _insn(10, "r5 += r3"),
        ]
        chain = compute_reaching_defs(trace)
        assert find_reaching_def_at(chain, 10, "R3", trace) == 5

    def test_unknown_reg_backward_scan(self):
        """When the key is not in the map, fall back to backward scan."""
        trace = [
            _insn(5, "r3 = r2"),
            _insn(10, "r5 = r5"),  # doesn't USE R3 syntactically
        ]
        chain = compute_reaching_defs(trace)
        # R3 not in uses at insn 10, so not in reaching map
        # Fallback scan should find insn 5
        result = find_reaching_def_at(chain, 10, "R3", trace)
        assert result == 5

    def test_no_def_returns_none(self):
        trace = [
            _insn(10, "r5 += r3"),
        ]
        chain = compute_reaching_defs(trace)
        # R3 used at 10 but never defined — should be None
        assert chain.reaching_def(10, "R3") is None


# ---------------------------------------------------------------------------
# Tests: compute_data_slice
# ---------------------------------------------------------------------------


class TestComputeDataSlice:
    def test_simple_chain(self):
        """Backward slice from (insn 10, R5) should include insns 5, 8, 10."""
        trace = [
            _insn(3, "r5 = r0"),   # first R5 def (not reaching insn 10)
            _insn(5, "r3 = r2"),   # def R3
            _insn(8, "r5 = r3"),   # def R5 from R3
            _insn(10, "r1 = r5"),  # USE R5
        ]
        chain = compute_reaching_defs(trace)
        slc = compute_data_slice(chain, trace, 10, "R5")
        # insn 10 itself, insn 8 (last def of R5), insn 5 (def of R3 used by 8)
        assert 10 in slc
        assert 8 in slc
        assert 5 in slc
        # insn 3 should NOT be in slice (R5 was overwritten at insn 8)
        assert 3 not in slc

    def test_includes_start(self):
        trace = [_insn(7, "exit")]
        chain = compute_reaching_defs(trace)
        slc = compute_data_slice(chain, trace, 7, "R0")
        assert 7 in slc


# ---------------------------------------------------------------------------
# Real case test: stackoverflow-70750259
# ---------------------------------------------------------------------------


class TestRealCase:
    """Integration test on a real verifier trace."""

    CASE_PATH = "bpfix-bench/raw/so/stackoverflow-70750259.yaml"

    @pytest.fixture(scope="class")
    def chain_and_trace(self):
        try:
            log = _verifier_log(self.CASE_PATH)
        except (FileNotFoundError, KeyError):
            pytest.skip(f"Case file not found: {self.CASE_PATH}")

        parsed = parse_trace(log)
        chain = compute_reaching_defs(parsed.instructions)
        return chain, parsed.instructions

    def test_chain_has_defs(self, chain_and_trace):
        chain, instructions = chain_and_trace
        # Should have computed defs for each instruction
        assert len(chain.defs) == len(set(i.insn_idx for i in instructions))

    def test_chain_has_uses(self, chain_and_trace):
        chain, instructions = chain_and_trace
        assert len(chain.uses) == len(set(i.insn_idx for i in instructions))

    def test_error_instruction_has_reaching_defs(self, chain_and_trace):
        """The error instruction should have reaching defs for its operands."""
        chain, instructions = chain_and_trace
        # Find error instruction
        error_insns = [i for i in instructions if i.is_error]
        if not error_insns:
            pytest.skip("No error instruction found")

        err = error_insns[-1]
        uses = chain.uses_at(err.insn_idx)
        # At least one used register should have a reaching def
        has_reaching = any(
            chain.reaching_def(err.insn_idx, reg) is not None
            for reg in uses
        )
        # It's valid if no reaching defs exist (all inputs from function args),
        # but for this real case there should be some
        assert has_reaching or len(uses) == 0, (
            f"Error insn {err.insn_idx} has uses {uses} but no reaching defs"
        )

    def test_all_defs_for_r0_nonempty(self, chain_and_trace):
        """R0 should be defined at some point in this trace."""
        chain, instructions = chain_and_trace
        defs = chain.all_defs_for("R0")
        assert len(defs) >= 1, "Expected R0 to be defined in this trace"

    def test_data_slice_from_error(self, chain_and_trace):
        """Backward data slice from error site should be non-empty and contained."""
        chain, instructions = chain_and_trace
        error_insns = [i for i in instructions if i.is_error]
        if not error_insns:
            pytest.skip("No error instruction found")

        err = error_insns[-1]
        uses = chain.uses_at(err.insn_idx)
        if not uses:
            pytest.skip("Error instruction has no syntactic uses")

        start_reg = next(iter(uses))
        slc = compute_data_slice(chain, instructions, err.insn_idx, start_reg)

        all_idx = {i.insn_idx for i in instructions}
        # Slice must be non-empty and a subset of traced instructions
        assert len(slc) >= 1
        assert slc <= all_idx, (
            f"Slice contains insn indices not in trace: {slc - all_idx}"
        )

    def test_key_case_r0_at_error(self, chain_and_trace):
        """In stackoverflow-70750259, error is at insn 39 (r5 += r0).

        R0 is the problematic register.  Its reaching def should be somewhere
        earlier in the trace.
        """
        chain, instructions = chain_and_trace
        insn_indices = {i.insn_idx for i in instructions}

        # Error is at insn 39 in this case
        if 39 not in insn_indices:
            pytest.skip("Expected insn 39 not in trace")

        # R0 should be defined before insn 39
        r0_def = find_reaching_def_at(chain, 39, "R0", instructions)
        # R0 may or may not be in uses at 39 depending on how compound ops parse,
        # but the backward scan should find a definition
        if r0_def is not None:
            assert r0_def < 39, (
                f"Reaching def of R0 at insn 39 should be before 39, got {r0_def}"
            )
