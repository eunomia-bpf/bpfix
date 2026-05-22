"""Generic trace monitor for proof obligation evaluation.

Evaluates a predicate's verification gap at each traced instruction to find
where a safety property was materially established, then where it was lost.
"""

from __future__ import annotations

from dataclasses import dataclass

from .opcode_safety import (
    CarrierSpec,
    OpcodeConditionPredicate,
    SafetyCondition,
    compute_condition_gap,
    instantiate_schema,
    normalize_pointer_kind,
)


@dataclass
class MonitorResult:
    """Result of monitoring a predicate over a trace."""

    proof_status: str
    """
    - 'never_established': predicate never reached gap=0 after a positive gap
    - 'established_then_lost': predicate reached gap=0, then later regressed
    - 'established_but_insufficient': predicate reached gap=0 but error still occurred
    - 'unknown': could not determine (e.g., no instructions, no predicate)
    """

    establish_site: int | None
    """Instruction index where the gap first transitioned from >0 to 0."""

    loss_site: int | None
    """Instruction index where the gap transitioned from 0 to >0."""

    loss_reason: str | None
    """Human-readable description of why P was violated at loss_site."""

    last_satisfied_insn: int | None = None
    """Last instruction index where predicate was still satisfied."""

    error_insn: int | None = None
    """Instruction index of the verifier error (if any)."""


@dataclass(frozen=True)
class LifecycleEvent:
    kind: str
    trace_pos: int
    insn_idx: int
    gap_before: int
    gap_after: int
    reason: str | None = None


@dataclass
class CarrierLifecycle:
    carrier: CarrierSpec | None
    events: list[LifecycleEvent]
    establish_site: int | None
    loss_site: int | None
    final_gap: int | None
    first_observed_gap: int | None
    proof_status: str


class CarrierBoundPredicate:
    """Predicate wrapper that only evaluates while a carrier alias matches."""

    def __init__(self, condition: SafetyCondition, carrier: CarrierSpec) -> None:
        self.condition = condition
        self.carrier = carrier
        self._delegate = OpcodeConditionPredicate(condition)

    @property
    def target_regs(self) -> list[str]:
        return [self.carrier.register]

    def evaluate(self, state: dict, insn=None) -> str:
        gap = self.compute_gap(state, insn)
        if gap is None:
            return "unknown"
        return "satisfied" if gap == 0 else "violated"

    def compute_gap(self, state: dict, insn=None) -> int | None:
        reg = state.get(self.carrier.register)
        if reg is None:
            return None
        if self.carrier.pointer_kind is not None:
            reg_type = getattr(reg, "type", "") or ""
            if normalize_pointer_kind(reg_type) != self.carrier.pointer_kind:
                return None
            if getattr(reg, "id", None) != self.carrier.provenance_id:
                return None
        return compute_condition_gap(self.condition, state)

    def describe_violation(self, state: dict, insn=None) -> str:
        return self._delegate.describe_violation(state, insn)


class TraceMonitor:
    """Evaluate a predicate over a sequence of TracedInstructions."""

    def monitor(self, predicate, traced_insns) -> MonitorResult:
        """Evaluate a predicate's verification gap at each instruction.

        Establishment is recorded only when the gap transitions from positive
        to zero. Vacuous satisfaction (gap already zero at the start) does not
        count as proof establishment.

        Args:
            predicate: A Predicate-like object with compute_gap(state) and
                       describe_violation(state) methods.
            traced_insns: Iterable of TracedInstruction objects.

        Returns:
            MonitorResult describing the proof status.
        """
        if predicate is None:
            return MonitorResult(
                proof_status="unknown",
                establish_site=None,
                loss_site=None,
                loss_reason="No predicate provided",
            )

        instructions = list(traced_insns)
        if not instructions:
            return MonitorResult(
                proof_status="unknown",
                establish_site=None,
                loss_site=None,
                loss_reason="No instructions in trace",
            )

        establish_site: int | None = None
        last_satisfied_insn: int | None = None
        loss_site: int | None = None
        loss_reason: str | None = None
        error_insn: int | None = None
        previous_gap: int | None = None
        proof_active = False

        for insn in instructions:
            if insn.is_error and error_insn is None:
                error_insn = insn.insn_idx

            # Evaluate predicate against the post-state first, fall back to pre-state
            # Post-state reflects what the verifier knows after this instruction
            state_to_check = insn.post_state or insn.pre_state

            if not state_to_check:
                if insn.is_error:
                    break
                continue

            gap = predicate.compute_gap(state_to_check, insn)
            if gap is None:
                if insn.is_error:
                    break
                continue

            if previous_gap is not None and previous_gap > 0 and gap == 0:
                if establish_site is None:
                    establish_site = insn.insn_idx
                proof_active = True
                loss_site = None
                loss_reason = None

            elif previous_gap is not None and previous_gap == 0 and gap > 0:
                if loss_site is None:
                    loss_site = insn.insn_idx
                    loss_reason = predicate.describe_violation(state_to_check, insn)
                proof_active = False

            if gap == 0 and proof_active:
                last_satisfied_insn = insn.insn_idx

            previous_gap = gap

            if insn.is_error:
                break

        # Classify the proof status
        if establish_site is None:
            proof_status = "never_established"
        elif loss_site is not None:
            proof_status = "established_then_lost"
        elif error_insn is not None:
            # Predicate was established but there's still an error —
            # possibly a different safety property failed
            proof_status = "established_but_insufficient"
        else:
            # No error and predicate was satisfied — unusual but possible
            proof_status = "established_but_insufficient"

        return MonitorResult(
            proof_status=proof_status,
            establish_site=establish_site,
            loss_site=loss_site,
            loss_reason=loss_reason,
            last_satisfied_insn=last_satisfied_insn,
            error_insn=error_insn,
        )

    def monitor_events(self, predicate, traced_insns) -> CarrierLifecycle:
        """Like monitor(), but retain every material establish/loss transition."""
        carrier = getattr(predicate, "carrier", None)
        if predicate is None:
            return CarrierLifecycle(
                carrier=carrier,
                events=[],
                establish_site=None,
                loss_site=None,
                final_gap=None,
                first_observed_gap=None,
                proof_status="unknown",
            )

        instructions = list(traced_insns)
        if not instructions:
            return CarrierLifecycle(
                carrier=carrier,
                events=[],
                establish_site=None,
                loss_site=None,
                final_gap=None,
                first_observed_gap=None,
                proof_status="unknown",
            )

        events: list[LifecycleEvent] = []
        establish_site: int | None = None
        loss_site: int | None = None
        error_insn: int | None = None
        previous_gap: int | None = None
        final_gap: int | None = None
        first_observed_gap: int | None = None

        for trace_pos, insn in enumerate(instructions):
            if insn.is_error and error_insn is None:
                error_insn = insn.insn_idx

            state_to_check = insn.post_state or insn.pre_state
            if not state_to_check:
                if insn.is_error:
                    break
                continue

            gap = predicate.compute_gap(state_to_check, insn)
            if gap is None:
                if insn.is_error:
                    break
                continue
            if first_observed_gap is None:
                first_observed_gap = gap

            if previous_gap is not None and previous_gap > 0 and gap == 0:
                events.append(LifecycleEvent(
                    kind="establish",
                    trace_pos=trace_pos,
                    insn_idx=insn.insn_idx,
                    gap_before=previous_gap,
                    gap_after=gap,
                ))
                if establish_site is None:
                    establish_site = insn.insn_idx
                loss_site = None

            elif previous_gap is not None and previous_gap == 0 and gap > 0:
                events.append(LifecycleEvent(
                    kind="loss",
                    trace_pos=trace_pos,
                    insn_idx=insn.insn_idx,
                    gap_before=previous_gap,
                    gap_after=gap,
                    reason=predicate.describe_violation(state_to_check, insn),
                ))
                if loss_site is None:
                    loss_site = insn.insn_idx

            previous_gap = gap
            final_gap = gap

            if insn.is_error:
                break

        if establish_site is None:
            proof_status = "never_established"
        elif loss_site is not None:
            proof_status = "established_then_lost"
        elif error_insn is not None:
            proof_status = "established_but_insufficient"
        else:
            proof_status = "established_but_insufficient"

        return CarrierLifecycle(
            carrier=carrier,
            events=events,
            establish_site=establish_site,
            loss_site=loss_site,
            final_gap=final_gap,
            first_observed_gap=first_observed_gap,
            proof_status=proof_status,
        )


def monitor_carriers(schema, carriers, traced_insns) -> dict[str, CarrierLifecycle]:
    """Monitor one instantiated predicate per carrier register."""
    monitor = TraceMonitor()
    lifecycles: dict[str, CarrierLifecycle] = {}
    for carrier in carriers:
        condition = instantiate_schema(schema, carrier)
        predicate = CarrierBoundPredicate(condition, carrier)
        lifecycles[carrier.register] = monitor.monitor_events(predicate, traced_insns)
    return lifecycles
