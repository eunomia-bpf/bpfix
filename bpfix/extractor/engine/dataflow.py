"""Reaching definitions analysis on the BPF verifier trace.

Computes syntactic def-use chains from instruction opcode semantics.
This is NOT abstract state (the verifier provides that as register types/bounds).
This is SYNTACTIC: "which instruction wrote to R3?"

The design is a single backward pass over the trace (trace order, not CFG order).
For the single DFS path the verifier explores toward the error, this is exact.
At merge points (from X to Y annotations) there may be multiple reaching defs;
we record the closest one in trace order, which is the one the verifier was
evaluating when it detected the error.

Key BPF opcode semantics encoded here (from ISA, not keyword heuristics):
  - ALU dst, src    -> DEF: dst,  USE: dst + src  (compound ops)
  - ALU dst = src   -> DEF: dst,  USE: src         (pure assignment)
  - LDX dst, [src+] -> DEF: dst,  USE: src
  - STX [dst+], src -> DEF: none (memory), USE: dst + src
  - ST  [dst+], imm -> DEF: none (memory), USE: dst
  - CALL            -> DEF: R0,   USE: R1-R5
  - EXIT            -> DEF: none, USE: R0
  - JMP/JMP32 cond  -> DEF: none, USE: branch-tested registers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..trace_parser import TracedInstruction

from .cfg_builder import TraceCFG


# ---------------------------------------------------------------------------
# Register-name helpers (shared patterns from _impl.py adapted here)
# ---------------------------------------------------------------------------

# Matches a single BPF register token: r0-r10 or w0-w10 (32-bit alias)
_REG_TOKEN = re.compile(r"\b[rRwW](\d+)\b")

# Matches the destination of "dst = ..." or "dst op= ..."
# Includes "s>>=" (signed right-shift) used by the BPF verifier disassembler.
_DST_RE = re.compile(
    r"^\s*(?P<dst>[rRwW]\d+)\s*(?P<op>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|s?>>=|>>>=)\s*",
    re.IGNORECASE,
)

# Memory load: dst = *(uN *)(src + off)
_LOAD_RE = re.compile(
    r"^\s*(?P<dst>[rRwW]\d+)\s*=\s*\*\([^)]+\)\s*\(\s*(?P<src>[rRwW]\d+)",
    re.IGNORECASE,
)

# Memory store register: *(uN *)(dst + off) = src
_STORE_REG_RE = re.compile(
    r"^\s*\*\([^)]+\)\s*\(\s*(?P<base>[rRwW]\d+)[^)]*\)\s*=\s*(?P<src>[rRwW]\d+)",
    re.IGNORECASE,
)

# Memory store immediate: *(uN *)(dst + off) = imm
_STORE_IMM_RE = re.compile(
    r"^\s*\*\([^)]+\)\s*\(\s*(?P<base>[rRwW]\d+)",
    re.IGNORECASE,
)

# Branch with register operands: "if rA op rB goto ..."
_BRANCH_REGS_RE = re.compile(
    r"^\s*if\s+(?P<left>[rRwW]\d+)\s*\S+\s*(?P<right>[rRwW]\d+)?",
    re.IGNORECASE,
)

# Byte-swap: "be16 rN" / "le32 rN"
_BYTESWAP_RE = re.compile(r"^\s*(?:be|le)\d+\s+(?P<dst>[rRwW]\d+)", re.IGNORECASE)

# CALL helper — "call <name>" or "call #imm"
_CALL_RE = re.compile(r"^\s*call\s", re.IGNORECASE)

# EXIT
_EXIT_RE = re.compile(r"^\s*exit\s*$", re.IGNORECASE)


def _norm(reg: str) -> str:
    """Normalize a register token to canonical uppercase form: R0..R10."""
    m = re.match(r"^[rRwW](\d+)$", reg.strip())
    if m:
        return f"R{m.group(1)}"
    return reg.upper()


def _all_regs(text: str) -> list[str]:
    """Return all register tokens in text, normalized, in order of appearance."""
    seen: list[str] = []
    for m in _REG_TOKEN.finditer(text):
        r = _norm(m.group(0))
        if r not in seen:
            seen.append(r)
    return seen


# ---------------------------------------------------------------------------
# Core semantic analysis: which registers does an instruction DEF and USE?
# ---------------------------------------------------------------------------


def extract_defs(bytecode: str) -> set[str]:
    """Return the set of registers DEFINED (written) by this instruction.

    Derived purely from BPF opcode semantics, not keyword heuristics.
    """
    if not bytecode:
        return set()

    text = bytecode.strip()

    # EXIT: no register definitions
    if _EXIT_RE.match(text):
        return set()

    # CALL: defines R0 (return value)
    if _CALL_RE.match(text):
        return {"R0"}

    # Memory load: dst = *(uN *)(src + off)  — defines dst
    m = _LOAD_RE.match(text)
    if m:
        return {_norm(m.group("dst"))}

    # Memory store register/imm: *(uN *)(base + off) = src/imm  — defines NONE
    if _STORE_REG_RE.match(text) or _STORE_IMM_RE.match(text):
        return set()

    # Branch instructions: "if ... goto ..." or "goto ..."  — define NONE
    if re.match(r"^\s*(?:if\s|goto\s)", text, re.IGNORECASE):
        return set()

    # Byte-swap: "be16 rN" / "le32 rN"  — defines the register in place
    m = _BYTESWAP_RE.match(text)
    if m:
        return {_norm(m.group("dst"))}

    # ALU assignment / compound:  dst op= src   or   dst = expr
    m = _DST_RE.match(text)
    if m:
        return {_norm(m.group("dst"))}

    return set()


def extract_uses(bytecode: str) -> set[str]:
    """Return the set of registers USED (read) by this instruction.

    Derived purely from BPF opcode semantics, not keyword heuristics.
    """
    if not bytecode:
        return set()

    text = bytecode.strip()

    # EXIT: uses R0 (return register)
    if _EXIT_RE.match(text):
        return {"R0"}

    # CALL: uses R1-R5 (argument registers)
    if _CALL_RE.match(text):
        return {"R1", "R2", "R3", "R4", "R5"}

    # Memory load: dst = *(uN *)(src + off)  — uses src
    m = _LOAD_RE.match(text)
    if m:
        return {_norm(m.group("src"))}

    # Memory store register: *(uN *)(base + off) = src  — uses base + src
    m = _STORE_REG_RE.match(text)
    if m:
        return {_norm(m.group("base")), _norm(m.group("src"))}

    # Memory store immediate: *(uN *)(base + off) = imm  — uses base
    m = _STORE_IMM_RE.match(text)
    if m:
        return {_norm(m.group("base"))}

    # Branch instructions: "if rA op rB goto ..." — uses rA (and rB if register)
    if re.match(r"^\s*if\s", text, re.IGNORECASE):
        mb = _BRANCH_REGS_RE.match(text)
        if mb:
            uses = {_norm(mb.group("left"))}
            right = mb.group("right")
            if right:
                uses.add(_norm(right))
            return uses
        # Fallback: collect all register refs in the condition part (before "goto")
        cond_part = re.split(r"\bgoto\b", text, 1)[0]
        return set(_all_regs(cond_part))

    # Unconditional goto: no register uses
    if re.match(r"^\s*goto\s", text, re.IGNORECASE):
        return set()

    # Byte-swap: "be16 rN" / "le32 rN"  — uses and redefines the same register
    m = _BYTESWAP_RE.match(text)
    if m:
        return {_norm(m.group("dst"))}

    # ALU compound (dst op= src): uses BOTH dst and src
    m = _DST_RE.match(text)
    if m:
        op = m.group("op")
        dst = _norm(m.group("dst"))
        rhs = text[m.end():]  # everything after the operator

        # Pure assignment "dst = src/imm" — uses only the source registers in rhs
        if op == "=":
            return set(_all_regs(rhs))

        # Compound op "dst op= rhs" — also reads dst
        uses = {dst}
        uses.update(_all_regs(rhs))
        return uses

    # Fallback: collect all register references
    return set(_all_regs(text))


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class Definition:
    """A single register definition site."""

    insn_idx: int
    register: str


@dataclass
class DefUseChain:
    """Syntactic def-use chains computed from a trace.

    ``defs[insn_idx]``      — set of registers DEFINED at instruction insn_idx
    ``uses[insn_idx]``      — set of registers USED at instruction insn_idx
    ``reaching[(insn_idx, reg)]`` — insn_idx of the instruction that last defined
                                    ``reg`` before instruction ``insn_idx`` in the
                                    trace, or None if no definition was found.
    """

    defs: dict[int, set[str]] = field(default_factory=dict)
    uses: dict[int, set[str]] = field(default_factory=dict)
    reaching: dict[tuple[int, str], int | None] = field(default_factory=dict)

    # -----------------------------------------------------------------------
    # Convenience helpers
    # -----------------------------------------------------------------------

    def reaching_def(self, insn_idx: int, register: str) -> int | None:
        """Return the instruction index that defines ``register`` before
        ``insn_idx``, or None."""
        return self.reaching.get((insn_idx, register))

    def defs_at(self, insn_idx: int) -> set[str]:
        """Registers defined at ``insn_idx``."""
        return self.defs.get(insn_idx, set())

    def uses_at(self, insn_idx: int) -> set[str]:
        """Registers used at ``insn_idx``."""
        return self.uses.get(insn_idx, set())

    def all_defs_for(self, register: str) -> list[int]:
        """All instruction indices that define ``register``, in trace order."""
        return sorted(
            idx for idx, regs in self.defs.items() if register in regs
        )


# ---------------------------------------------------------------------------
# Core analysis: compute_reaching_defs
# ---------------------------------------------------------------------------


def compute_reaching_defs(
    traced_instructions: list,  # list[TracedInstruction]
    cfg: TraceCFG | None = None,
) -> DefUseChain:
    """Compute syntactic def-use chains from the trace.

    Algorithm
    ---------
    Single forward pass over the trace (in trace order):
      1. For each instruction, extract DEFs and USEs from opcode semantics.
      2. For each USE at this instruction, look up the current reaching def
         from the ``current_def`` map and record it.
      3. Update the ``current_def`` map with this instruction's DEFs.

    This is a single-path analysis — trace order is the execution order the
    verifier followed.  For BPF programs (which are DAGs or bounded loops),
    the verifier explores one DFS path to each error.  On this path, the
    most-recently-written definition is the reaching definition.

    The CFG parameter is reserved for merge-point-aware analysis but is not
    required for the single-path case.

    Args:
        traced_instructions: List of TracedInstruction objects from parse_trace().
        cfg: Optional TraceCFG.  Currently unused; accepted for future extension.

    Returns:
        DefUseChain with defs, uses, and reaching maps populated.
    """
    chain = DefUseChain()

    # current_def[reg] = insn_idx of the most recent instruction that wrote reg
    current_def: dict[str, int] = {}

    for insn in traced_instructions:
        idx = insn.insn_idx
        bytecode = insn.bytecode or ""

        # Compute DEFs and USEs for this instruction
        insn_defs = extract_defs(bytecode)
        insn_uses = extract_uses(bytecode)

        chain.defs[idx] = insn_defs
        chain.uses[idx] = insn_uses

        # Record reaching definitions for each USE at this instruction
        for reg in insn_uses:
            key = (idx, reg)
            chain.reaching[key] = current_def.get(reg)  # None if no prior def

        # Update reaching-def map with DEFs from this instruction
        for reg in insn_defs:
            current_def[reg] = idx

    return chain


# ---------------------------------------------------------------------------
# Backward-slice helpers (convenience layer on top of DefUseChain)
# ---------------------------------------------------------------------------


def find_reaching_def_at(
    chain: DefUseChain,
    insn_idx: int,
    register: str,
    traced_instructions: list | None = None,
) -> int | None:
    """Return the insn_idx of the instruction that defined ``register`` before
    ``insn_idx``, performing a backward scan if the precomputed reaching map
    does not have the answer.

    This handles cases where we want to look up the reaching def for a register
    that was not in the precomputed USE set (e.g., for an error register that
    was not syntactically read by the error instruction itself, but carried
    bad state).

    Args:
        chain: A DefUseChain from compute_reaching_defs().
        insn_idx: The instruction index we want the reaching def for.
        register: Canonical register name (e.g., "R3").
        traced_instructions: Original instruction list.  Used for fallback
                             backward scan when the register isn't in reaching.

    Returns:
        The defining instruction index, or None.
    """
    key = (insn_idx, register)
    if key in chain.reaching:
        return chain.reaching[key]

    # Fallback: backward scan through the instruction list
    if traced_instructions is None:
        return None

    found_self = False
    for insn in reversed(traced_instructions):
        if insn.insn_idx == insn_idx:
            found_self = True
            continue
        if not found_self:
            continue
        if register in chain.defs.get(insn.insn_idx, set()):
            return insn.insn_idx

    return None


def compute_data_slice(
    chain: DefUseChain,
    traced_instructions: list,
    start_insn_idx: int,
    start_register: str,
    max_depth: int = 20,
) -> set[int]:
    """Compute a backward data-dependence slice from (start_insn_idx, start_register).

    Follows DEF-USE chains backward from the starting criterion, collecting
    all instruction indices that contribute to the value of ``start_register``
    at ``start_insn_idx``.

    Args:
        chain: Precomputed DefUseChain.
        traced_instructions: Original instruction list.
        start_insn_idx: Error (or criterion) instruction index.
        start_register: The register of interest at the error site.
        max_depth: Maximum recursion depth to prevent cycles in loopy traces.

    Returns:
        Set of instruction indices in the data slice (includes start_insn_idx).
    """
    slice_insns: set[int] = set()
    worklist: list[tuple[int, str, int]] = [
        (start_insn_idx, start_register, 0)
    ]
    visited: set[tuple[int, str]] = set()

    while worklist:
        idx, reg, depth = worklist.pop()

        key = (idx, reg)
        if key in visited or depth > max_depth:
            continue
        visited.add(key)
        slice_insns.add(idx)

        # Find the instruction that defined reg at idx
        def_idx = find_reaching_def_at(chain, idx, reg, traced_instructions)
        if def_idx is None:
            continue

        slice_insns.add(def_idx)

        # Find all registers used by the defining instruction and recurse
        for used_reg in chain.uses_at(def_idx):
            worklist.append((def_idx, used_reg, depth + 1))

    return slice_insns
