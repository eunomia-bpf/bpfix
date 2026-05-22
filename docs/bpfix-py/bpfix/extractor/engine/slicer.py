"""Principled backward slice combining data dependence + control dependence.

This module computes a backward program slice from a criterion (insn_idx, register)
using both:
  1. Data dependence: which instructions contributed to the value of a register
     (via reaching definitions / def-use chains from dataflow.py)
  2. Control dependence: which branch instructions determine whether a given
     instruction executes at all (from control_dep.py)

The full backward slice is data_deps ∪ control_deps.

This replaces the old heuristic mark_precise-following approach. The result
is a principled causal chain grounded in program analysis theory.

Reference: Weiser (1984), "Program Slicing".
           Ottenstein & Ottenstein (1984), "The Program Dependence Graph in a
           Software Development Environment."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..trace_parser import TracedInstruction

from .cfg_builder import TraceCFG, build_cfg
from .control_dep import ControlDep, compute_control_dependence, controlling_branches
from .dataflow import DefUseChain, compute_data_slice, compute_reaching_defs


# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------


@dataclass
class BackwardSlice:
    """Result of backward slicing from a criterion.

    Attributes
    ----------
    criterion_insn:
        The instruction index of the slicing criterion.
    criterion_register:
        The register of interest at the criterion instruction.
    data_deps:
        Set of instruction indices in the data dependence slice.
        Includes the criterion instruction itself, plus all instructions
        that transitively contribute to the value of ``criterion_register``
        at ``criterion_insn`` via def-use chains.
    control_deps:
        Set of instruction indices in the control dependence slice.
        For each instruction in ``data_deps``, this includes all branch
        instructions that control whether that instruction executes.
        Also includes the data deps of those branch conditions.
    full_slice:
        ``data_deps ∪ control_deps``.
    ordered:
        ``full_slice`` sorted in ascending instruction index order (earliest
        instruction first, criterion last).
    """

    criterion_insn: int
    criterion_register: str
    data_deps: set[int] = field(default_factory=set)
    control_deps: set[int] = field(default_factory=set)
    full_slice: set[int] = field(default_factory=set)
    ordered: list[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core slicer
# ---------------------------------------------------------------------------


def backward_slice(
    traced_instructions: list,  # list[TracedInstruction]
    criterion_insn: int,
    criterion_register: str,
    cfg: TraceCFG | None = None,
    max_depth: int = 25,
) -> BackwardSlice:
    """Compute backward slice from (criterion_insn, criterion_register).

    Algorithm
    ---------
    1. Build CFG if not provided (needed for control dependence).
    2. Compute reaching definitions (DefUseChain) via dataflow.py.
    3. Compute data dependence slice (transitive def-use from criterion)
       using compute_data_slice().
    4. Compute control dependence graph (CDG) using control_dep.py.
    5. For each instruction in the data slice, add its controlling branches
       to the control_deps set.
    6. For each added branch, also trace the data deps of its condition
       registers (so we know *why* the branch went that way).
    7. Return data_deps ∪ control_deps as the full slice.

    The slice answers: "what instructions could have influenced register R
    at instruction N?"

    Parameters
    ----------
    traced_instructions:
        List of TracedInstruction objects from parse_trace().
    criterion_insn:
        The instruction index of the slicing criterion (e.g., the error site).
    criterion_register:
        The register of interest at the criterion instruction (e.g., "R0").
        Must be in canonical uppercase form (R0..R10).
    cfg:
        Optional pre-built TraceCFG.  If None, one is built from
        traced_instructions.
    max_depth:
        Maximum recursion depth for the data slice (prevents infinite loops
        in traces with back-edges from bounded loops).

    Returns
    -------
    BackwardSlice
        The computed slice with data_deps, control_deps, full_slice, and
        ordered instruction list.
    """
    if not traced_instructions:
        return BackwardSlice(
            criterion_insn=criterion_insn,
            criterion_register=criterion_register,
        )

    # Step 1: Build CFG if not provided.
    if cfg is None:
        cfg = build_cfg(traced_instructions)

    # Step 2: Compute reaching definitions (def-use chains).
    chain: DefUseChain = compute_reaching_defs(traced_instructions, cfg)

    # Step 3: Compute data dependence slice from the criterion.
    #
    # Strategy: compute_data_slice starts from (criterion_insn, criterion_register)
    # and follows reaching defs backward.  Two cases:
    #
    # Case A: criterion_insn USES criterion_register (e.g., error at "r5 += r0";
    #         criterion_register = "R5" or "R0").  compute_data_slice will find
    #         the reaching def and recurse into its uses.
    #
    # Case B: criterion_insn DEFINES criterion_register (e.g., "r5 = r3";
    #         criterion_register = "R5").  compute_data_slice will add criterion_insn
    #         but find no reaching def (because insn is the def, not a user).
    #         We fix this by also slicing from each register USED by criterion_insn.
    data_deps: set[int] = compute_data_slice(
        chain,
        traced_instructions,
        criterion_insn,
        criterion_register,
        max_depth=max_depth,
    )

    # Handle Case B: if data_deps is just the criterion itself and the criterion
    # instruction defines criterion_register, trace its uses too.
    criterion_defs = chain.defs.get(criterion_insn, set())
    criterion_uses = chain.uses.get(criterion_insn, set())
    if criterion_register in criterion_defs and criterion_uses:
        # The criterion instruction IS the producer — trace its input registers.
        for used_reg in criterion_uses:
            extra = compute_data_slice(
                chain,
                traced_instructions,
                criterion_insn,
                used_reg,
                max_depth=max_depth,
            )
            data_deps.update(extra)
    # Always ensure the criterion insn is included.
    if criterion_insn in {insn.insn_idx for insn in traced_instructions}:
        data_deps.add(criterion_insn)

    # Step 4: Compute control dependence graph.
    # Build an insn_map so opcode-based branch detection works for partial CFGs.
    insn_map: dict[int, object] = {}
    for insn in traced_instructions:
        if insn.insn_idx not in insn_map:
            insn_map[insn.insn_idx] = insn

    cd: ControlDep = compute_control_dependence(cfg, insn_map=insn_map)

    # Step 5: For each instruction in the data slice, find its controlling branches.
    control_deps: set[int] = set()
    branch_worklist: list[int] = []

    for insn_idx in data_deps:
        branches = controlling_branches(cd, insn_idx)
        for branch_idx in branches:
            if branch_idx not in control_deps:
                control_deps.add(branch_idx)
                branch_worklist.append(branch_idx)

    # Step 6: For each controlling branch, also trace data deps of branch condition
    # registers.  This answers: "what instructions determined how this branch went?"
    # We do this iteratively until no new instructions are discovered.
    visited_branches: set[int] = set(branch_worklist)
    branch_data_deps: set[int] = set()

    while branch_worklist:
        branch_idx = branch_worklist.pop()

        # Find which registers the branch instruction uses (its condition registers).
        branch_uses = chain.uses_at(branch_idx)
        if not branch_uses:
            # No register uses recorded — fall back to checking the bytecode.
            # (This happens if the branch idx is not in the chain because it was
            # added via a "from X to Y" annotation rather than trace order.)
            continue

        # Compute data slice for each condition register of the branch.
        for reg in branch_uses:
            reg_slice = compute_data_slice(
                chain,
                traced_instructions,
                branch_idx,
                reg,
                max_depth=max_depth,
            )
            branch_data_deps.update(reg_slice)

            # Also find controlling branches of these newly added instructions.
            for new_insn in reg_slice:
                new_branches = controlling_branches(cd, new_insn)
                for new_branch in new_branches:
                    if new_branch not in visited_branches:
                        visited_branches.add(new_branch)
                        control_deps.add(new_branch)
                        branch_worklist.append(new_branch)

    # Merge branch data deps into control_deps (they contribute to control flow).
    control_deps.update(branch_data_deps)

    # Step 7: Compose the full slice.
    full_slice: set[int] = data_deps | control_deps

    # Restrict to instruction indices that actually appear in the trace
    # (filter out any phantom indices from CFG edges, etc.).
    all_trace_idxs: set[int] = {insn.insn_idx for insn in traced_instructions}
    full_slice &= all_trace_idxs
    data_deps &= all_trace_idxs
    control_deps &= all_trace_idxs

    # Sort in ascending order (earliest first → criterion last).
    ordered: list[int] = sorted(full_slice)

    return BackwardSlice(
        criterion_insn=criterion_insn,
        criterion_register=criterion_register,
        data_deps=data_deps,
        control_deps=control_deps,
        full_slice=full_slice,
        ordered=ordered,
    )
