"""Tests for gap-based proof establishment in TraceMonitor."""

from __future__ import annotations

from bpfix.extractor.engine.monitor import TraceMonitor
from bpfix.extractor.engine.opcode_safety import (
    OpcodeConditionPredicate,
    SafetyCondition,
    SafetyDomain,
)
from bpfix.extractor.trace_parser import RegisterState, TracedInstruction


class PacketAccessGap:
    def __init__(self, register: str, access_size: int) -> None:
        self.register = register
        self.access_size = access_size

    def compute_gap(self, state: dict[str, RegisterState], insn=None) -> int | None:
        reg = state.get(self.register)
        if reg is None or reg.range is None or reg.off is None:
            return None
        return max(0, reg.off + self.access_size - reg.range)

    def describe_violation(self, state: dict[str, RegisterState], insn=None) -> str:
        return "packet access exceeds proven range"


def _rs(type_: str = "scalar", **kwargs) -> RegisterState:
    return RegisterState(type=type_, **kwargs)


def _insn(
    idx: int,
    bytecode: str,
    *,
    pre: dict[str, RegisterState] | None = None,
    post: dict[str, RegisterState] | None = None,
    is_error: bool = False,
) -> TracedInstruction:
    return TracedInstruction(
        insn_idx=idx,
        bytecode=bytecode,
        source_line=None,
        pre_state=dict(pre or {}),
        post_state=dict(post or {}),
        backtrack=None,
        is_error=is_error,
        error_text="reject" if is_error else None,
    )


def test_vacuous_satisfaction_does_not_create_establishment():
    predicate = OpcodeConditionPredicate(
        SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register="R10",
            required_property="must be a valid pointer type",
        )
    )
    instructions = [
        _insn(0, "r1 = r10", post={"R10": _rs("fp")}),
        _insn(1, "r0 = 0", post={"R10": _rs("fp")}, is_error=True),
    ]

    result = TraceMonitor().monitor(predicate, instructions)

    assert result.proof_status == "never_established"
    assert result.establish_site is None
    assert result.loss_site is None
    assert result.last_satisfied_insn is None


def test_positive_gap_to_zero_creates_establishment():
    predicate = PacketAccessGap("R3", access_size=4)
    instructions = [
        _insn(0, "r3 = r1", post={"R3": _rs("pkt", off=8, range=10)}),
        _insn(1, "if r2 > r1 goto pc+1", post={"R3": _rs("pkt", off=8, range=12)}),
        _insn(2, "r0 = *(u32 *)(r3 +0)", post={"R3": _rs("pkt", off=8, range=12)}, is_error=True),
    ]

    result = TraceMonitor().monitor(predicate, instructions)

    assert result.proof_status == "established_but_insufficient"
    assert result.establish_site == 1
    assert result.loss_site is None
    assert result.last_satisfied_insn == 2


def test_gap_increase_after_establishment_creates_loss():
    predicate = PacketAccessGap("R3", access_size=4)
    instructions = [
        _insn(0, "r3 = r1", post={"R3": _rs("pkt", off=8, range=10)}),
        _insn(1, "if r2 > r1 goto pc+1", post={"R3": _rs("pkt", off=8, range=12)}),
        _insn(2, "r3 += r4", post={"R3": _rs("pkt", off=8, range=9)}, is_error=True),
    ]

    result = TraceMonitor().monitor(predicate, instructions)

    assert result.proof_status == "established_then_lost"
    assert result.establish_site == 1
    assert result.loss_site == 2
    assert result.last_satisfied_insn == 1
    assert result.loss_reason is not None
