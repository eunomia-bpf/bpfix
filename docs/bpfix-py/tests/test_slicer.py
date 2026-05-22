"""Tests for bpfix/extractor/engine/slicer.py — principled backward slice.

Tests cover:
  1. Simple data-only slice: A defines R3, B uses R3 and defines R5,
     criterion=(B, R5) → slice includes A.
  2. Data + control: branch at C controls D, D defines R5,
     criterion=(D, R5) → slice includes C and D.
  3. Real case: stackoverflow-70750259, slice from error instruction backward.
  4. Compare slice with mark_precise chain (they should overlap significantly).
  5. Edge cases: empty trace, criterion not in trace, no defs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

from bpfix.extractor.trace_parser import TracedInstruction
from bpfix.extractor.engine.slicer import BackwardSlice, backward_slice
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
# Test 1: Simple data-only slice
# ---------------------------------------------------------------------------
#
#  insn 0: r3 = r1      (A: defines R3)
#  insn 1: r5 = r3      (B: uses R3, defines R5) ← criterion (1, R5)
#
# Backward slice from (1, R5):
#   - insn 1 defines R5 ← in slice
#   - R5 is defined by insn 1 which uses R3
#   - R3 is defined by insn 0 ← in slice
#
# Expected: {0, 1}


class TestSimpleDataSlice:
    def _build_trace(self) -> list[TracedInstruction]:
        return [
            _insn(0, "r3 = r1", opcode_hex="bf"),  # A: DEF R3, USE R1
            _insn(1, "r5 = r3", opcode_hex="bf"),  # B: DEF R5, USE R3
        ]

    def test_slice_includes_def_a(self):
        """Slice from (1, R5) must include insn 0 (def of R3 used by insn 1)."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=1, criterion_register="R5")
        assert 0 in slc.full_slice, (
            f"insn 0 (def of R3) must be in slice; full_slice={slc.full_slice}"
        )

    def test_slice_includes_criterion(self):
        """Criterion instruction must always be in the slice."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=1, criterion_register="R5")
        assert 1 in slc.full_slice

    def test_slice_in_data_deps(self):
        """Both insns are in data_deps (purely data dependence, no control)."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=1, criterion_register="R5")
        assert 0 in slc.data_deps
        assert 1 in slc.data_deps

    def test_no_control_deps_in_linear_trace(self):
        """A linear trace with no branches has no control dependence."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=1, criterion_register="R5")
        assert slc.control_deps == set(), (
            f"Expected no control deps in linear trace; got {slc.control_deps}"
        )

    def test_ordered_is_sorted(self):
        """Ordered list must be sorted ascending."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=1, criterion_register="R5")
        assert slc.ordered == sorted(slc.ordered)

    def test_full_slice_is_union(self):
        """full_slice == data_deps | control_deps."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=1, criterion_register="R5")
        assert slc.full_slice == slc.data_deps | slc.control_deps

    def test_overwrite_not_in_slice(self):
        """An earlier def that was overwritten should NOT appear in the slice."""
        trace = [
            _insn(0, "r3 = r1", opcode_hex="bf"),   # first def of R3 (overwritten)
            _insn(1, "r3 = r2", opcode_hex="bf"),   # second def of R3 (reaching)
            _insn(2, "r5 = r3", opcode_hex="bf"),   # USE R3; criterion
        ]
        slc = backward_slice(trace, criterion_insn=2, criterion_register="R5")
        # insn 1 is in slice (reaches insn 2), insn 0 is NOT (overwritten at 1)
        assert 1 in slc.full_slice
        assert 2 in slc.full_slice
        assert 0 not in slc.full_slice, (
            f"Overwritten def (insn 0) should NOT be in slice; got {slc.full_slice}"
        )


# ---------------------------------------------------------------------------
# Test 2: Data + control dependence
# ---------------------------------------------------------------------------
#
# Trace:
#  insn 0: r1 = 1                            (entry)
#  insn 1: if r1 > 0 goto pc+1   (C: conditional branch; fall→2, target→3)
#  insn 2: r5 = 10                           (then-arm: D defines R5)
#  insn 3: exit                              (merge/exit)
#
# Criterion: (2, R5)
# Data deps: insn 2 (defines R5 directly) → slice = {2}
# Control deps: insn 2 is control-dependent on insn 1 (the branch)
#   → add insn 1 to control_deps
#   → insn 1 uses R1, R1 is defined at insn 0 → add insn 0 as branch data dep
#
# Expected full_slice: {0, 1, 2}


class TestDataPlusControlSlice:
    def _build_trace(self) -> list[TracedInstruction]:
        return [
            _insn(0, "r1 = 1", opcode_hex="b7"),           # DEF R1
            # Conditional: fall-through=2, target=3 (pc+1 → 1+1+1=3)
            _insn(1, "if r1 > 0 goto pc+1", opcode_hex="2d"),  # branch
            _insn(2, "r5 = 10", opcode_hex="b7"),          # D: DEF R5
            _insn(3, "exit", opcode_hex="95"),
        ]

    def test_control_dep_in_slice(self):
        """Branch (insn 1) should appear in the slice (controls insn 2)."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=2, criterion_register="R5")
        assert 1 in slc.full_slice, (
            f"Branch insn 1 should be in slice as control dep; full_slice={slc.full_slice}"
        )

    def test_branch_in_control_deps(self):
        """The controlling branch should appear in control_deps."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=2, criterion_register="R5")
        assert 1 in slc.control_deps, (
            f"Branch insn 1 should be in control_deps; control_deps={slc.control_deps}"
        )

    def test_criterion_in_data_deps(self):
        """Criterion instruction (insn 2) is always in data_deps."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=2, criterion_register="R5")
        assert 2 in slc.data_deps

    def test_branch_condition_def_in_slice(self):
        """The def of the branch condition register (insn 0) should be in slice."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=2, criterion_register="R5")
        # insn 0 defines R1 which is used by the branch at insn 1
        assert 0 in slc.full_slice, (
            f"Branch condition def (insn 0) should be in slice; full_slice={slc.full_slice}"
        )

    def test_full_slice_coverage(self):
        """Full slice should include insns 0, 1, 2 (not 3: exit not involved)."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=2, criterion_register="R5")
        assert 0 in slc.full_slice
        assert 1 in slc.full_slice
        assert 2 in slc.full_slice


# ---------------------------------------------------------------------------
# Test 3: Longer data chain
# ---------------------------------------------------------------------------
#
#  insn 0: r1 = 100       (def R1)
#  insn 1: r2 = r1        (def R2 from R1)
#  insn 2: r3 = r2        (def R3 from R2)
#  insn 3: r5 += r3       (use R3, def R5) ← criterion (3, R5)
#
# Expected data_deps: {0, 1, 2, 3} (transitive chain)


class TestTransitiveDataChain:
    def _build_trace(self) -> list[TracedInstruction]:
        return [
            _insn(0, "r1 = 100", opcode_hex="b7"),
            _insn(1, "r2 = r1", opcode_hex="bf"),
            _insn(2, "r3 = r2", opcode_hex="bf"),
            _insn(3, "r5 += r3", opcode_hex="0f"),  # compound: uses R5 and R3
        ]

    def test_transitive_chain(self):
        """All instructions in the def-use chain should be in data_deps."""
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=3, criterion_register="R5")
        # The chain: 3 uses R3 (def at 2) → 2 uses R2 (def at 1) → 1 uses R1 (def at 0)
        assert 2 in slc.data_deps, f"insn 2 should be in data_deps; got {slc.data_deps}"
        assert 1 in slc.data_deps, f"insn 1 should be in data_deps; got {slc.data_deps}"
        assert 0 in slc.data_deps, f"insn 0 should be in data_deps; got {slc.data_deps}"
        assert 3 in slc.data_deps

    def test_ordered_ascending(self):
        trace = self._build_trace()
        slc = backward_slice(trace, criterion_insn=3, criterion_register="R5")
        assert slc.ordered == sorted(slc.ordered)
        assert slc.ordered[-1] <= 3  # criterion is at or near the end


# ---------------------------------------------------------------------------
# Test 4: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_trace(self):
        """Empty trace returns an empty BackwardSlice."""
        slc = backward_slice([], criterion_insn=0, criterion_register="R0")
        assert slc.full_slice == set()
        assert slc.data_deps == set()
        assert slc.control_deps == set()
        assert slc.ordered == []

    def test_single_instruction(self):
        """Single exit instruction — only the criterion in the slice."""
        trace = [_insn(0, "exit", opcode_hex="95")]
        slc = backward_slice(trace, criterion_insn=0, criterion_register="R0")
        # R0 is used by EXIT; criterion is in slice
        assert 0 in slc.full_slice

    def test_criterion_not_in_trace(self):
        """If criterion insn is not in trace, we get a graceful minimal result."""
        trace = [
            _insn(5, "r0 = 1", opcode_hex="b7"),
        ]
        # criterion at insn 99 which doesn't exist
        slc = backward_slice(trace, criterion_insn=99, criterion_register="R0")
        # Should not crash; slice may be empty (99 not in trace)
        assert isinstance(slc, BackwardSlice)
        assert slc.criterion_insn == 99

    def test_register_never_defined(self):
        """If the criterion register was never defined, slice contains only criterion."""
        trace = [
            _insn(0, "r0 = 1", opcode_hex="b7"),
            _insn(1, "exit", opcode_hex="95"),
        ]
        # R7 is never defined
        slc = backward_slice(trace, criterion_insn=1, criterion_register="R7")
        # criterion (1) in slice; no def of R7 → data_deps minimal
        assert isinstance(slc, BackwardSlice)
        # Should not include insn 0 since R0 def doesn't affect R7
        assert 0 not in slc.data_deps

    def test_returns_backwardslice_dataclass(self):
        """Return type is BackwardSlice."""
        trace = [_insn(0, "r0 = 1", opcode_hex="b7")]
        slc = backward_slice(trace, criterion_insn=0, criterion_register="R0")
        assert isinstance(slc, BackwardSlice)
        assert slc.criterion_insn == 0
        assert slc.criterion_register == "R0"

    def test_full_slice_subset_of_trace(self):
        """full_slice must be a subset of the instruction indices in the trace."""
        trace = [
            _insn(0, "r1 = 1", opcode_hex="b7"),
            _insn(1, "r0 = r1", opcode_hex="bf"),
            _insn(2, "exit", opcode_hex="95"),
        ]
        slc = backward_slice(trace, criterion_insn=2, criterion_register="R0")
        all_idxs = {i.insn_idx for i in trace}
        assert slc.full_slice <= all_idxs, (
            f"full_slice contains indices not in trace: {slc.full_slice - all_idxs}"
        )


# ---------------------------------------------------------------------------
# Test 5: Real case — stackoverflow-70750259
# ---------------------------------------------------------------------------


CASE_PATH = "bpfix-bench/raw/so/stackoverflow-70750259.yaml"


class TestRealCase:
    """Integration test on the stackoverflow-70750259 real verifier trace."""

    @pytest.fixture(scope="class")
    def parsed(self):
        try:
            log = _verifier_log(CASE_PATH)
        except (FileNotFoundError, KeyError):
            pytest.skip(f"Case file not found: {CASE_PATH}")
        return parse_trace(log)

    @pytest.fixture(scope="class")
    def slice_result(self, parsed):
        instructions = parsed.instructions
        error_insns = [i for i in instructions if i.is_error]
        if not error_insns:
            pytest.skip("No error instruction in trace")
        error_insn = error_insns[-1]

        # Use R0 as the criterion register (common for this case: r5 += r0 at insn 39)
        # Try to find the first used register at the error instruction
        from bpfix.extractor.engine.dataflow import compute_reaching_defs
        chain = compute_reaching_defs(instructions)
        uses = chain.uses_at(error_insn.insn_idx)
        if not uses:
            pytest.skip("Error instruction has no syntactic uses")
        reg = next(iter(uses))

        return backward_slice(
            instructions,
            criterion_insn=error_insn.insn_idx,
            criterion_register=reg,
        )

    def test_slice_nonempty(self, slice_result):
        """The backward slice from the error should be non-empty."""
        assert len(slice_result.full_slice) >= 1

    def test_criterion_in_slice(self, slice_result):
        """The criterion instruction must be in the slice."""
        assert slice_result.criterion_insn in slice_result.full_slice

    def test_full_slice_is_union(self, slice_result):
        """full_slice must equal data_deps ∪ control_deps."""
        assert slice_result.full_slice == slice_result.data_deps | slice_result.control_deps

    def test_ordered_is_sorted(self, slice_result):
        """Ordered list must be sorted ascending."""
        assert slice_result.ordered == sorted(slice_result.ordered)

    def test_ordered_matches_full_slice(self, slice_result):
        """Ordered must contain same elements as full_slice."""
        assert set(slice_result.ordered) == slice_result.full_slice

    def test_full_slice_subset_of_trace(self, parsed, slice_result):
        """full_slice must be subset of trace instruction indices."""
        all_idxs = {i.insn_idx for i in parsed.instructions}
        assert slice_result.full_slice <= all_idxs

    def test_slice_has_data_deps(self, slice_result):
        """Data deps should be non-trivial for a real trace."""
        assert len(slice_result.data_deps) >= 1

    def test_slice_contains_earlier_instructions(self, slice_result):
        """Slice should contain instructions earlier than the criterion."""
        earlier = {idx for idx in slice_result.full_slice
                   if idx < slice_result.criterion_insn}
        assert len(earlier) >= 1, (
            f"Expected earlier instructions in slice; full_slice={slice_result.full_slice}"
        )

    def test_overlap_with_mark_precise(self, parsed, slice_result):
        """The slice should overlap with backtracking/mark_precise info.

        mark_precise is the verifier's own backward analysis; our slice should
        include at least some of the same instructions.

        This is a weak test: we just verify the slice is semantically plausible
        (it covers some instructions that backtracking also considers).
        """
        # Collect all instructions referenced by backtrack info
        backtrack_insns: set[int] = set()
        for insn in parsed.instructions:
            if insn.backtrack is not None:
                bt = insn.backtrack
                last_idx = getattr(bt, "last_idx", None)
                first_idx = getattr(bt, "first_idx", None)
                if last_idx is not None:
                    backtrack_insns.add(last_idx)
                if first_idx is not None:
                    backtrack_insns.add(first_idx)

        if not backtrack_insns:
            pytest.skip("No backtrack info in this trace")

        overlap = slice_result.full_slice & backtrack_insns
        # We expect at least SOME overlap since both are backward analyses
        # from the error site.  Accept zero if the slice is tiny.
        if len(slice_result.full_slice) > 3:
            assert len(overlap) >= 1, (
                f"Expected slice to overlap with mark_precise instructions; "
                f"slice={slice_result.full_slice}, backtrack={backtrack_insns}"
            )


# ---------------------------------------------------------------------------
# Test 6: Pre-built CFG is accepted
# ---------------------------------------------------------------------------


def test_accepts_prebuilt_cfg() -> None:
    """backward_slice() should accept an externally provided TraceCFG."""
    from bpfix.extractor.engine.cfg_builder import build_cfg

    trace = [
        _insn(0, "r3 = r1", opcode_hex="bf"),
        _insn(1, "r5 = r3", opcode_hex="bf"),
    ]
    cfg = build_cfg(trace)
    slc = backward_slice(trace, criterion_insn=1, criterion_register="R5", cfg=cfg)
    assert 0 in slc.full_slice
    assert 1 in slc.full_slice


# ---------------------------------------------------------------------------
# Test 7: Dataclass field invariants
# ---------------------------------------------------------------------------


def test_backwardslice_fields() -> None:
    """BackwardSlice fields have correct types and defaults."""
    slc = BackwardSlice(criterion_insn=5, criterion_register="R3")
    assert slc.data_deps == set()
    assert slc.control_deps == set()
    assert slc.full_slice == set()
    assert slc.ordered == []
    assert slc.criterion_insn == 5
    assert slc.criterion_register == "R3"
