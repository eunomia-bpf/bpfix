"""Transition analyzer — classify per-instruction semantic effects on proof-relevant state.

This is the core "abstract state transition analysis" module. It classifies each
instruction's effect on proof-relevant register state, producing a TransitionChain
that identifies where the proof was established and where it broke.

Key design:
- Uses interval arithmetic for bounds classification (not just field comparison)
- Detects branch merges as precision-loss points
- Produces rich REASON fields: "OR operation destroyed scalar tracking", not just "bounds widened"
- Handles None values (unknown bounds) correctly
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List

from ..shared_utils import is_pointer_type_name, is_nullable_pointer_type


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class TransitionEffect(Enum):
    NARROWING = "narrowing"      # bounds tightened, type refined — proof strengthened
    WIDENING = "widening"        # bounds loosened, precision lost — proof weakened
    DESTROYING = "destroying"    # proof-relevant property completely broken
    NEUTRAL = "neutral"          # no effect on proof-relevant state


@dataclass
class TransitionDetail:
    insn_idx: int
    effect: TransitionEffect
    register: str              # which register was affected
    field: str                 # which field changed (range, umax, type, etc.)
    before: str                # value before (human-readable string)
    after: str                 # value after (human-readable string)
    reason: str                # WHY it changed (opcode, branch merge, spill/fill, etc.)
    source_text: str | None    # BTF source line if available


@dataclass
class TransitionChain:
    """The causal chain of state-degrading instructions leading to failure."""
    proof_status: str          # never_established, established_then_lost, etc.
    establish_point: TransitionDetail | None  # where proof was first established (narrowing)
    loss_point: TransitionDetail | None       # where proof was destroyed/widened
    chain: List[TransitionDetail]             # full chain of proof-relevant transitions


# ---------------------------------------------------------------------------
# Branch-merge detection helpers
# ---------------------------------------------------------------------------

# Regex to detect "from X to Y:" state annotation lines — these are join points
_FROM_TO_RE = re.compile(r"^\s*from\s+(\d+)\s+to\s+(\d+)\s*:")

# Regex to detect stack spill/fill operations.
# Verifier uses forms like: *(u64 *)(fp-8) = r1  (spill)
#                           r1 = *(u64 *)(fp-8)  (fill)
# The "(fp-" suffix is the tell.
_STACK_SPILL_RE = re.compile(r"\*\(u\d+\s*\*?\)\s*\(fp-", re.IGNORECASE)
_STACK_FILL_RE = re.compile(r"[rw]\d+\s*=\s*\*\(u\d+\s*\*?\)\s*\(fp-", re.IGNORECASE)

# Regex to detect ALU operations that commonly destroy precision
_ALU_OP_RE = re.compile(
    r"""
    (?P<dst>[rw]\d+)\s*            # destination register
    (?P<op>
        \|=|\^=|<<=|>>=|>>=|       # bit ops / shifts
        &=|\+=|-=|\*=|/=|%=|       # arithmetic
        =                          # assignment
    )\s*
    (?P<rhs>.+)                    # right-hand side
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Opcode mnemonics that commonly widen/destroy scalar precision
_PRECISION_DESTROYING_OPS = frozenset({
    "or", "|=", "^=", "xor",       # bitwise OR / XOR
    "<<=", "lsh", ">>>=", "rsh",   # shifts
    "*=", "mul",                    # multiplication
    "be16", "be32", "be64",         # byte-swap
    "le16", "le32", "le64",
})


# ---------------------------------------------------------------------------
# Core analyzer
# ---------------------------------------------------------------------------

class TransitionAnalyzer:
    """Analyze per-instruction semantic effects on proof-relevant abstract state."""

    def analyze(self, traced_insns, proof_registers: set[str]) -> TransitionChain:
        """For each instruction, classify its effect on proof-relevant registers.

        Args:
            traced_insns: List of TracedInstruction from trace_parser.
            proof_registers: Set of register names relevant to the proof obligation
                           (e.g., {"R0", "R3"} for a packet access involving those regs).

        Returns:
            TransitionChain with classified transitions.
        """
        instructions = list(traced_insns)
        if not proof_registers:
            return TransitionChain(
                proof_status="unknown",
                establish_point=None,
                loss_point=None,
                chain=[],
            )

        all_transitions: List[TransitionDetail] = []

        establish_point: TransitionDetail | None = None
        loss_point: TransitionDetail | None = None
        proof_established = False

        for insn in instructions:
            # Only examine registers that the upstream proof analysis identified
            # as relevant to the violated safety condition.
            relevant_regs = proof_registers

            for reg in sorted(relevant_regs):
                pre = insn.pre_state.get(reg)
                post = insn.post_state.get(reg)

                if pre is None and post is None:
                    continue

                detail = self.classify_transition(
                    reg=reg,
                    pre_state=pre,
                    post_state=post,
                    opcode=insn.bytecode,
                    insn_idx=insn.insn_idx,
                    source_text=insn.source_line,
                )

                if detail.effect == TransitionEffect.NEUTRAL:
                    continue

                all_transitions.append(detail)

                # Track proof establishment / loss
                if detail.effect == TransitionEffect.NARROWING:
                    if not proof_established:
                        proof_established = True
                        establish_point = detail
                elif detail.effect in (TransitionEffect.DESTROYING, TransitionEffect.WIDENING):
                    if proof_established and loss_point is None:
                        # Only mark as loss if it's definitely destroying, or widening that
                        # reaches an unbounded state
                        if detail.effect == TransitionEffect.DESTROYING:
                            loss_point = detail
                        elif detail.effect == TransitionEffect.WIDENING and self._is_significant_widening(detail):
                            loss_point = detail

        # Determine proof status
        if not proof_established:
            proof_status = "never_established"
        elif loss_point is not None:
            proof_status = "established_then_lost"
        else:
            proof_status = "established_but_insufficient"

        return TransitionChain(
            proof_status=proof_status,
            establish_point=establish_point,
            loss_point=loss_point,
            chain=all_transitions,
        )

    def classify_transition(
        self,
        reg: str,
        pre_state,
        post_state,
        opcode: str,
        insn_idx: int = 0,
        source_text: str | None = None,
    ) -> TransitionDetail:
        """Classify a single register's state change at one instruction.

        This is the CORE of the analysis — not just "did the value change?"
        but "what KIND of change, and WHY?"

        Args:
            reg: Register name (e.g., "R0")
            pre_state: RegisterState before the instruction (may be None)
            post_state: RegisterState after the instruction (may be None)
            opcode: The instruction bytecode text (e.g., "r0 |= r6")
            insn_idx: Instruction index (for context)
            source_text: BTF source annotation if available

        Returns:
            TransitionDetail with effect classification and reason.
        """
        # Case 1: register not present in either state — neutral
        if pre_state is None and post_state is None:
            return TransitionDetail(
                insn_idx=insn_idx,
                effect=TransitionEffect.NEUTRAL,
                register=reg,
                field="none",
                before="absent",
                after="absent",
                reason="register not in scope",
                source_text=source_text,
            )

        # Case 2: register newly appeared (no pre-state) — could be narrowing if type is concrete
        if pre_state is None:
            post_desc = _describe_state(post_state)
            is_ptr = is_pointer_type_name(post_state.type)
            is_scalar_bounded = (
                _is_scalar_like(post_state) and
                post_state.umax is not None and
                post_state.umax < (1 << 63)
            )
            if is_ptr or is_scalar_bounded:
                return TransitionDetail(
                    insn_idx=insn_idx,
                    effect=TransitionEffect.NARROWING,
                    register=reg,
                    field="type",
                    before="absent",
                    after=post_desc,
                    reason=self._infer_reason(opcode, None, post_state, TransitionEffect.NARROWING),
                    source_text=source_text,
                )
            return TransitionDetail(
                insn_idx=insn_idx,
                effect=TransitionEffect.NEUTRAL,
                register=reg,
                field="type",
                before="absent",
                after=post_desc,
                reason="register first seen",
                source_text=source_text,
            )

        # Case 3: register disappeared after instruction — destroying if it was meaningful
        if post_state is None:
            if is_pointer_type_name(pre_state.type):
                return TransitionDetail(
                    insn_idx=insn_idx,
                    effect=TransitionEffect.DESTROYING,
                    register=reg,
                    field="type",
                    before=_describe_state(pre_state),
                    after="absent",
                    reason=self._infer_reason(opcode, pre_state, None, TransitionEffect.DESTROYING),
                    source_text=source_text,
                )
            return TransitionDetail(
                insn_idx=insn_idx,
                effect=TransitionEffect.NEUTRAL,
                register=reg,
                field="type",
                before=_describe_state(pre_state),
                after="absent",
                reason="register left scope",
                source_text=source_text,
            )

        # Case 4: both states present — compare them
        pre_type = pre_state.type
        post_type = post_state.type

        # ── Type change check (highest priority) ────────────────────────────
        if pre_type != post_type:
            type_effect, type_field, type_reason = self._classify_type_change(pre_type, post_type)
            # Append opcode context to the semantic reason rather than replacing it,
            # so TYPE_DOWNGRADE/NULL_RESOLVED labels are preserved.
            detailed_reason = self._infer_reason(opcode, pre_state, post_state, type_effect)
            if detailed_reason != "unknown operation" and detailed_reason not in type_reason:
                type_reason = f"{type_reason} (via {detailed_reason})"

            return TransitionDetail(
                insn_idx=insn_idx,
                effect=type_effect,
                register=reg,
                field=type_field,
                before=_describe_state(pre_state),
                after=_describe_state(post_state),
                reason=type_reason,
                source_text=source_text,
            )

        # ── Range change check (for pointer types) ───────────────────────────
        if is_pointer_type_name(pre_type):
            pre_range = pre_state.range
            post_range = post_state.range
            if pre_range != post_range:
                range_effect, range_reason = self._classify_range_change(pre_range, post_range)
                # Append opcode context while preserving the semantic label
                opcode_reason = self._infer_reason(opcode, pre_state, post_state, range_effect)
                if opcode_reason != "unknown operation" and opcode_reason not in range_reason:
                    range_reason = f"{range_reason} (via {opcode_reason})"
                return TransitionDetail(
                    insn_idx=insn_idx,
                    effect=range_effect,
                    register=reg,
                    field="range",
                    before=f"r={pre_range}",
                    after=f"r={post_range}",
                    reason=range_reason,
                    source_text=source_text,
                )

            # Offset change on pointer — may indicate arithmetic
            pre_off = pre_state.off
            post_off = post_state.off
            if pre_off != post_off:
                # Pointer arithmetic — may be ok or may be widening
                effect = TransitionEffect.NEUTRAL
                if post_state.range is not None and post_state.range == 0 and (pre_state.range or 0) > 0:
                    effect = TransitionEffect.DESTROYING
                return TransitionDetail(
                    insn_idx=insn_idx,
                    effect=effect,
                    register=reg,
                    field="off",
                    before=f"off={pre_off}",
                    after=f"off={post_off}",
                    reason=self._infer_reason(opcode, pre_state, post_state, effect),
                    source_text=source_text,
                )

        # ── Bounds change check (for scalar types) ───────────────────────────
        if _is_scalar_like(pre_state) and _is_scalar_like(post_state):
            bounds_effect, bounds_field, bounds_reason = self._classify_bounds_change(
                pre_state, post_state
            )
            if bounds_effect != TransitionEffect.NEUTRAL:
                detailed_reason = self._infer_reason(opcode, pre_state, post_state, bounds_effect)
                if detailed_reason != "unknown operation":
                    bounds_reason = detailed_reason
                return TransitionDetail(
                    insn_idx=insn_idx,
                    effect=bounds_effect,
                    register=reg,
                    field=bounds_field,
                    before=_describe_bounds(pre_state),
                    after=_describe_bounds(post_state),
                    reason=bounds_reason,
                    source_text=source_text,
                )

        # ── Var_off change (tnum precision) ─────────────────────────────────
        if pre_state.var_off != post_state.var_off:
            tnum_effect, tnum_reason = self._classify_tnum_change(pre_state.var_off, post_state.var_off)
            if tnum_effect != TransitionEffect.NEUTRAL:
                return TransitionDetail(
                    insn_idx=insn_idx,
                    effect=tnum_effect,
                    register=reg,
                    field="var_off",
                    before=f"var_off={pre_state.var_off}",
                    after=f"var_off={post_state.var_off}",
                    reason=self._infer_reason(opcode, pre_state, post_state, tnum_effect),
                    source_text=source_text,
                )

        # No meaningful change
        return TransitionDetail(
            insn_idx=insn_idx,
            effect=TransitionEffect.NEUTRAL,
            register=reg,
            field="none",
            before=_describe_state(pre_state),
            after=_describe_state(post_state),
            reason="no proof-relevant change",
            source_text=source_text,
        )

    # -------------------------------------------------------------------------
    # Classification helpers
    # -------------------------------------------------------------------------

    def _classify_bounds_change(self, pre, post) -> tuple[TransitionEffect, str, str]:
        """Use interval arithmetic to classify bounds changes.

        Returns (effect, field_name, reason).

        Interval containment:
        - [umin_post, umax_post] ⊆ [umin_pre, umax_pre]: NARROWING
        - [umin_pre, umax_pre] ⊆ [umin_post, umax_post]: WIDENING
        - Bounds lost entirely: DESTROYING
        - Otherwise: NEUTRAL
        """
        # Check for bounds collapse (previously bounded → unbounded)
        pre_umin = pre.umin
        pre_umax = pre.umax
        post_umin = post.umin
        post_umax = post.umax

        pre_smin = pre.smin
        pre_smax = pre.smax
        post_smin = post.smin
        post_smax = post.smax

        # Bounds collapse: had known bounds, now unbounded
        pre_bounded = pre_umax is not None or pre_umin is not None
        post_bounded = post_umax is not None or post_umin is not None

        if pre_bounded and not post_bounded:
            return (
                TransitionEffect.DESTROYING,
                "umax",
                f"bounds completely lost: [{pre_umin}, {pre_umax}] -> unbounded",
            )

        if not pre_bounded and not post_bounded:
            return TransitionEffect.NEUTRAL, "none", "both unbounded"

        # Use unsigned interval
        pre_lo = pre_umin if pre_umin is not None else 0
        pre_hi = pre_umax if pre_umax is not None else (1 << 64) - 1
        post_lo = post_umin if post_umin is not None else 0
        post_hi = post_umax if post_umax is not None else (1 << 64) - 1

        # NARROWING: post interval ⊆ pre interval
        if post_lo >= pre_lo and post_hi <= pre_hi:
            if post_lo == pre_lo and post_hi == pre_hi:
                # Same bounds — check signed bounds
                if pre_smin is not None and post_smin is not None and post_smin > pre_smin:
                    return (
                        TransitionEffect.NARROWING,
                        "smin",
                        f"signed lower bound tightened: smin {pre_smin} -> {post_smin}",
                    )
                if pre_smax is not None and post_smax is not None and post_smax < pre_smax:
                    return (
                        TransitionEffect.NARROWING,
                        "smax",
                        f"signed upper bound tightened: smax {pre_smax} -> {post_smax}",
                    )
                return TransitionEffect.NEUTRAL, "none", "bounds unchanged"
            return (
                TransitionEffect.NARROWING,
                "umax",
                f"unsigned interval tightened: [{pre_lo}, {pre_hi}] -> [{post_lo}, {post_hi}]",
            )

        # WIDENING: pre interval ⊆ post interval
        if pre_lo >= post_lo and pre_hi <= post_hi:
            return (
                TransitionEffect.WIDENING,
                "umax",
                f"unsigned interval widened: [{pre_lo}, {pre_hi}] -> [{post_lo}, {post_hi}]",
            )

        # Overlapping but neither contains the other — widening in one direction
        if post_hi > pre_hi:
            return (
                TransitionEffect.WIDENING,
                "umax",
                f"upper bound increased: umax {pre_hi} -> {post_hi}",
            )
        if post_lo < pre_lo:
            return (
                TransitionEffect.WIDENING,
                "umin",
                f"lower bound decreased: umin {pre_lo} -> {post_lo}",
            )

        # Default: treat as narrowing if upper bound decreased
        if post_hi < pre_hi:
            return (
                TransitionEffect.NARROWING,
                "umax",
                f"upper bound decreased: umax {pre_hi} -> {post_hi}",
            )

        return TransitionEffect.NEUTRAL, "none", "bounds effectively unchanged"

    def _classify_type_change(self, pre_type: str, post_type: str) -> tuple[TransitionEffect, str, str]:
        """Classify type transitions.

        Returns (effect, field_name, reason).

        Cases:
        - pointer → scalar: DESTROYING (TYPE_DOWNGRADE)
        - *_or_null → concrete pointer: NARROWING (NULL_RESOLVED)
        - concrete pointer → *_or_null: WIDENING (NULL_INTRODUCED)
        - scalar → pointer: NARROWING (TYPE_UPGRADE, rare but possible after helper call)
        """
        pre_is_ptr = is_pointer_type_name(pre_type)
        post_is_ptr = is_pointer_type_name(post_type)
        pre_is_scalar = _is_scalar_type_name(pre_type)
        post_is_scalar = _is_scalar_type_name(post_type)
        pre_is_nullable = is_nullable_pointer_type(pre_type)
        post_is_nullable = is_nullable_pointer_type(post_type)

        # pointer → scalar: TYPE_DOWNGRADE (DESTROYING)
        if pre_is_ptr and post_is_scalar:
            return (
                TransitionEffect.DESTROYING,
                "type",
                f"TYPE_DOWNGRADE: pointer type {pre_type!r} downgraded to scalar {post_type!r}",
            )

        # *_or_null → concrete pointer: NARROWING (null check resolved)
        if pre_is_nullable and post_is_ptr and not post_is_nullable:
            return (
                TransitionEffect.NARROWING,
                "type",
                f"NULL_RESOLVED: {pre_type!r} narrowed to non-null {post_type!r}",
            )

        # concrete pointer → *_or_null: WIDENING (null may have been introduced)
        if pre_is_ptr and not pre_is_nullable and post_is_nullable:
            return (
                TransitionEffect.WIDENING,
                "type",
                f"NULL_INTRODUCED: concrete {pre_type!r} widened to nullable {post_type!r}",
            )

        # scalar → pointer: NARROWING (type upgrade)
        if pre_is_scalar and post_is_ptr:
            return (
                TransitionEffect.NARROWING,
                "type",
                f"TYPE_UPGRADE: scalar {pre_type!r} upgraded to pointer {post_type!r}",
            )

        # pointer type changed (e.g., pkt -> pkt_end, map_ptr -> map_value)
        if pre_is_ptr and post_is_ptr and pre_type != post_type:
            # This is a type change among pointers — usually neutral or narrowing
            return (
                TransitionEffect.NEUTRAL,
                "type",
                f"pointer type changed: {pre_type!r} -> {post_type!r}",
            )

        # No meaningful change
        return TransitionEffect.NEUTRAL, "type", f"type unchanged: {pre_type!r} -> {post_type!r}"

    def _classify_range_change(self, pre_range, post_range) -> tuple[TransitionEffect, str]:
        """Classify range changes for pointer types.

        Returns (effect, reason).

        - range increased: NARROWING (more accessible bytes proven)
        - range decreased to 0: DESTROYING (RANGE_LOSS — no bytes proven accessible)
        - range decreased but > 0: WIDENING (fewer bytes proven)
        """
        pre_r = pre_range or 0
        post_r = post_range or 0

        if pre_r == 0 and post_r > 0:
            return (
                TransitionEffect.NARROWING,
                f"RANGE_ESTABLISHED: range 0 -> {post_r} (packet bounds proof established)",
            )
        if pre_r > 0 and post_r == 0:
            return (
                TransitionEffect.DESTROYING,
                f"RANGE_LOSS: packet/memory range proof destroyed (r={pre_r} -> r=0)",
            )
        if pre_r > 0 and post_r > 0:
            if post_r == pre_r:
                return TransitionEffect.NEUTRAL, "range unchanged"
            if post_r > pre_r:
                return (
                    TransitionEffect.NARROWING,
                    f"RANGE_EXPANDED: range {pre_r} -> {post_r} (more bytes proven safe)",
                )
            else:
                return (
                    TransitionEffect.WIDENING,
                    f"RANGE_REDUCED: range {pre_r} -> {post_r} (fewer bytes proven safe)",
                )
        return TransitionEffect.NEUTRAL, "range unchanged"

    def _classify_tnum_change(self, pre_var_off, post_var_off) -> tuple[TransitionEffect, str]:
        """Classify tnum (value+mask) precision changes.

        In the verifier, var_off is stored as (value; mask).
        A larger mask means less precision (more unknown bits).
        A smaller mask means more precision (tighter tnum tracking).

        Returns (effect, reason).
        """
        if pre_var_off is None or post_var_off is None:
            return TransitionEffect.NEUTRAL, "var_off unknown"

        pre_mask = _parse_tnum_mask(pre_var_off)
        post_mask = _parse_tnum_mask(post_var_off)

        if pre_mask is None or post_mask is None:
            return TransitionEffect.NEUTRAL, "var_off could not be parsed"

        if post_mask > pre_mask:
            return (
                TransitionEffect.WIDENING,
                f"TNUM_PRECISION_LOST: mask grew {hex(pre_mask)} -> {hex(post_mask)} (more unknown bits)",
            )
        if post_mask < pre_mask:
            return (
                TransitionEffect.NARROWING,
                f"TNUM_PRECISION_GAINED: mask shrank {hex(pre_mask)} -> {hex(post_mask)} (fewer unknown bits)",
            )
        return TransitionEffect.NEUTRAL, "tnum precision unchanged"

    def _infer_reason(self, insn, pre, post, effect) -> str:
        """Infer WHY the state changed based on the opcode.

        Returns a human-readable string explaining the cause of the transition.
        This is what makes this "analysis" not just "comparison".
        """
        if not insn:
            return "unknown operation"

        bytecode = insn.strip().lower() if isinstance(insn, str) else ""

        # Stack operations
        if _STACK_FILL_RE.search(bytecode):
            return "stack fill: register loaded from stack slot (type info may be lost)"
        if _STACK_SPILL_RE.search(bytecode):
            return "stack spill: register stored to stack slot"

        # Function call — R0 gets return value, R1-R5 are clobbered
        if bytecode.startswith("call "):
            call_name = bytecode[5:].strip()
            return f"function call to {call_name!r} — return value in R0, args R1-R5 clobbered"

        # ALU operation analysis
        alu_match = _ALU_OP_RE.match(bytecode)
        if alu_match:
            op = alu_match.group("op").strip()
            dst = alu_match.group("dst")
            rhs = alu_match.group("rhs").strip()

            if op == "|=":
                return (
                    f"OR operation ({dst} |= {rhs}) — bitwise OR destroys scalar tracking "
                    f"by setting unknown bits, causing bounds collapse"
                )
            if op == "^=":
                return (
                    f"XOR operation ({dst} ^= {rhs}) — XOR may destroy scalar precision"
                )
            if op == "<<=":
                return (
                    f"left-shift ({dst} <<= {rhs}) — shift may lose high-bit precision"
                )
            if op == ">>=":
                return (
                    f"right-shift ({dst} >>= {rhs}) — shift may introduce sign uncertainty"
                )
            if op == "&=":
                return (
                    f"AND operation ({dst} &= {rhs}) — bitwise AND narrows value range"
                )
            if op == "+=":
                return (
                    f"ADD operation ({dst} += {rhs}) — pointer arithmetic or scalar add"
                )
            if op == "-=":
                return (
                    f"SUB operation ({dst} -= {rhs}) — may tighten or widen bounds"
                )
            if op == "*=":
                return (
                    f"MUL operation ({dst} *= {rhs}) — multiplication can dramatically widen bounds"
                )
            if op == "=":
                # Assignment — could be from memory, another register, or constant
                if rhs.startswith("*("):
                    return f"memory load ({dst} = {rhs}) — loaded value has type/bounds from memory"
                if re.match(r"^-?\d+$", rhs) or re.match(r"^0x[0-9a-f]+$", rhs):
                    return f"constant assignment ({dst} = {rhs})"
                return f"register copy ({dst} = {rhs})"

        # Byte-swap instructions (be16/be32/be64, le16/le32/le64)
        if re.match(r"^(?:be|le)\d+\s", bytecode):
            op = bytecode.split()[0]
            return (
                f"byte-swap ({op}) — may destroy scalar bounds tracking because "
                f"verifier cannot track precise output range after endian conversion"
            )

        # Branch instruction — this is a join point if we see "from X to Y"
        if re.match(r"^if\s", bytecode) or re.match(r"^goto\s", bytecode):
            return "branch instruction — state may be JOIN of multiple paths"

        # Memory load
        if re.match(r"^[rw]\d+\s*=\s*\*\(", bytecode):
            return "memory load — loaded value type/bounds depend on memory contents"

        # Memory store
        if re.match(r"^\*\(", bytecode):
            return "memory store — does not change register state"

        # Branch-merge annotation detection (from X to Y)
        from_to = _FROM_TO_RE.match(bytecode)
        if from_to:
            from_idx = from_to.group(1)
            to_idx = from_to.group(2)
            return (
                f"branch merge from insn {from_idx} to {to_idx} — "
                f"verifier JOINs states from multiple paths, often causing WIDENING"
            )

        return f"instruction: {insn!r}"

    def _is_significant_widening(self, detail: TransitionDetail) -> bool:
        """Determine if a widening transition is significant enough to mark as loss point."""
        # Destroying effects are always significant
        if detail.effect == TransitionEffect.DESTROYING:
            return True
        # Widening that removes bounds entirely
        if "unbounded" in detail.reason.lower() or "bounds lost" in detail.reason.lower():
            return True
        if "range_loss" in detail.reason.upper():
            return True
        if "type_downgrade" in detail.reason.upper():
            return True
        return False


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def analyze_transitions(
    traced_insns,
    proof_registers: set[str] | None = None,
) -> TransitionChain:
    """Convenience wrapper around TransitionAnalyzer.analyze().

    Args:
        traced_insns: List of TracedInstruction from trace_parser.
        proof_registers: Set of register names relevant to the proof.
                         If empty/None, no transition story is synthesized.

    Returns:
        TransitionChain with classified transitions.
    """
    analyzer = TransitionAnalyzer()
    return analyzer.analyze(traced_insns, proof_registers or set())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_scalar_like(state) -> bool:
    """Check if a RegisterState represents a scalar (non-pointer) type."""
    if state is None:
        return False
    return _is_scalar_type_name(state.type)


def _is_scalar_type_name(type_name: str) -> bool:
    lowered = type_name.lower()
    return (
        lowered.startswith("inv")
        or lowered.startswith("scalar")
        or lowered == "unknown"
    )


def _describe_state(state) -> str:
    """Produce a human-readable description of a RegisterState."""
    if state is None:
        return "absent"
    parts = [state.type]
    if state.id is not None:
        parts.append(f"id={state.id}")
    if state.off is not None:
        parts.append(f"off={state.off}")
    if state.range is not None:
        parts.append(f"r={state.range}")
    if state.umin is not None:
        parts.append(f"umin={state.umin}")
    if state.umax is not None:
        parts.append(f"umax={state.umax}")
    if state.var_off is not None:
        parts.append(f"var_off={state.var_off}")
    return ",".join(parts)


def _describe_bounds(state) -> str:
    """Produce a bounds-focused description of a RegisterState."""
    if state is None:
        return "absent"
    parts = []
    if state.umin is not None:
        parts.append(f"umin={state.umin}")
    if state.umax is not None:
        parts.append(f"umax={state.umax}")
    if state.smin is not None:
        parts.append(f"smin={state.smin}")
    if state.smax is not None:
        parts.append(f"smax={state.smax}")
    if state.var_off is not None:
        parts.append(f"var_off={state.var_off}")
    if not parts:
        return f"{state.type}(unbounded)"
    return f"{state.type}({','.join(parts)})"


def _parse_tnum_mask(var_off: str) -> int | None:
    """Parse the mask from a var_off string like '(0x0; 0xff)' or '(value; mask)'.

    Returns the integer mask value, or None if parsing fails.
    """
    if not var_off:
        return None
    # Format: (value; mask)
    match = re.match(r"\(([^;]+);\s*([^)]+)\)", var_off.strip())
    if match:
        mask_str = match.group(2).strip()
        try:
            return int(mask_str, 0)
        except ValueError:
            return None
    return None
