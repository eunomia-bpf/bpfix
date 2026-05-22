"""Control dependence analysis for BPF verifier trace CFGs.

Computes the control dependence graph (CDG) from a TraceCFG using the
post-dominator tree.  No keyword heuristics — only CFG structure.

Algorithm:
  1. Add a virtual EXIT node that all real exit nodes connect to.
  2. Reverse the CFG (swap all edges) to get the reverse CFG.
  3. Compute dominators on the reverse CFG → these are the post-dominators
     on the original CFG (iterative dataflow, O(N^2) for small N).
  4. Extract the immediate post-dominator for each node.
  5. For each conditional branch A with successors {S1, S2}:
       for each Si, walk up the post-dominator tree from Si until
       reaching ipdom(A).  Every node on this walk is control-dependent on A.

Reference: Cytron et al. (1989), §3.  Ferrante, Ottenstein & Warren (1987).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .cfg_builder import TraceCFG

from .cfg_builder import (
    is_unconditional_goto,
    _get_opcode_info,
)

# Sentinel for the virtual EXIT node.
_VIRT_EXIT = -1


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ControlDep:
    """Control dependence information for a CFG.

    ``deps[B]`` is the set of branch instruction indices that instruction B
    is control-dependent on.  An instruction that is not in ``deps`` (or whose
    set is empty) is unconditionally executed (not control-dependent on any
    explored branch).
    """

    deps: dict[int, set[int]] = field(default_factory=dict)
    # Immediate post-dominator for each instruction index.
    # ipdom[n] == n for nodes that post-dominate themselves (the virtual exit
    # and, typically, instructions with no successors in the explored CFG).
    ipdom: dict[int, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper: reverse post-order traversal
# ---------------------------------------------------------------------------


def _reverse_postorder(succ: dict[int, set[int]], entry: int) -> list[int]:
    """Return nodes in reverse post-order (RPO) from *entry* in the graph
    given by *succ*.

    RPO is the order used by the iterative dominator algorithm: each node
    appears after all its dominator-relevant predecessors.
    """
    visited: set[int] = set()
    postorder: list[int] = []

    # Iterative DFS.
    stack: list[tuple[int, bool]] = [(entry, False)]
    while stack:
        node, returning = stack.pop()
        if returning:
            postorder.append(node)
            continue
        if node in visited:
            continue
        visited.add(node)
        stack.append((node, True))
        for child in sorted(succ.get(node, set()), reverse=True):
            if child not in visited:
                stack.append((child, False))

    postorder.reverse()  # RPO = reverse of post-order
    return postorder


# ---------------------------------------------------------------------------
# Post-dominator computation
# ---------------------------------------------------------------------------


def _compute_postdom(
    insn_successors: dict[int, set[int]],
    insn_predecessors: dict[int, set[int]],
    all_nodes: set[int],
    exit_nodes: set[int],
) -> dict[int, int]:
    """Compute the immediate post-dominator for every node in *all_nodes*.

    Returns ipdom: dict[int, int] where ipdom[n] is the immediate post-
    dominator of n.  For nodes that post-dominate themselves (virtual exit),
    ipdom[n] = n.

    Steps
    -----
    1.  Create a virtual EXIT node (_VIRT_EXIT) with edges from every real
        exit node.
    2.  Build the *reverse* CFG (swap all edges, plus the virtual EXIT edges).
    3.  Run the iterative dominator algorithm on the reverse CFG starting from
        _VIRT_EXIT.  The dominators in the reverse CFG are the post-dominators
        in the original CFG.
    4.  Extract the immediate post-dominator (closest strict post-dominator).
    """
    # ------------------------------------------------------------------
    # Step 1: Reverse CFG + virtual EXIT node.
    # ------------------------------------------------------------------
    # rev_succ[n] = successors of n in the reverse CFG
    #             = predecessors of n in the original CFG
    rev_succ: dict[int, set[int]] = {n: set() for n in all_nodes}
    rev_succ[_VIRT_EXIT] = set()

    # Reverse original edges.
    for src, dsts in insn_successors.items():
        if src not in rev_succ:
            rev_succ[src] = set()
        for dst in dsts:
            if dst not in rev_succ:
                rev_succ[dst] = set()
            rev_succ[dst].add(src)

    # Add virtual EXIT -> real exit nodes.
    for en in exit_nodes:
        if en not in rev_succ:
            rev_succ[en] = set()
        rev_succ[_VIRT_EXIT].add(en)

    # All nodes in reverse CFG.
    rev_all = all_nodes | {_VIRT_EXIT}

    # ------------------------------------------------------------------
    # Step 2: Iterative dominator computation on the reverse CFG.
    # ------------------------------------------------------------------
    # dom[n] = set of nodes that dominate n in the reverse CFG.
    # Initialise: dom[_VIRT_EXIT] = {_VIRT_EXIT}, dom[n] = all_nodes for n != _VIRT_EXIT.
    dom: dict[int, set[int]] = {}
    dom[_VIRT_EXIT] = {_VIRT_EXIT}
    for n in all_nodes:
        dom[n] = set(rev_all)  # pessimistic initialisation

    # Rev predecessors (= original successors, plus _VIRT_EXIT->exit edges).
    # We need: who are the predecessors of n in the reverse CFG?
    # In the reverse CFG, pred(n) = { m | n ∈ rev_succ[m] }.
    rev_pred: dict[int, set[int]] = {n: set() for n in rev_all}
    for src, dsts in rev_succ.items():
        for dst in dsts:
            if dst not in rev_pred:
                rev_pred[dst] = set()
            rev_pred[dst].add(src)

    # Iterative fixed-point.
    rpo = _reverse_postorder(rev_succ, _VIRT_EXIT)
    changed = True
    while changed:
        changed = False
        for n in rpo:
            if n == _VIRT_EXIT:
                continue
            preds = rev_pred.get(n, set())
            if not preds:
                new_dom = {n}
            else:
                # Intersection of dom sets of all predecessors.
                pred_iter = iter(preds)
                new_dom = set(dom.get(next(pred_iter), set(rev_all)))
                for p in pred_iter:
                    new_dom &= dom.get(p, set(rev_all))
                new_dom.add(n)
            if new_dom != dom.get(n):
                dom[n] = new_dom
                changed = True

    # ------------------------------------------------------------------
    # Step 3: Extract immediate post-dominator.
    # ------------------------------------------------------------------
    # ipdom[n] = the closest strict dominator of n in the reverse CFG
    #           = the immediate post-dominator of n in the original CFG.
    ipdom: dict[int, int] = {}

    for n in rev_all:
        strict_doms = dom.get(n, {n}) - {n}
        if not strict_doms:
            # n is only dominated by itself (e.g., _VIRT_EXIT).
            ipdom[n] = n
            continue
        # Immediate dominator = the strict dominator that dominates all other
        # strict dominators of n.  In dominator theory, idom(n) is the unique
        # node d in strict_doms such that d dominates every other element of
        # strict_doms — i.e., every other strict dom of n appears in dom[d].
        best: int | None = None
        for candidate in strict_doms:
            # candidate is the idom if it dominates every other strict dom of n.
            # "candidate dominates other" means other ∈ dom[candidate].
            if all(
                other in dom.get(candidate, set()) or candidate == other
                for other in strict_doms
            ):
                best = candidate
                break
        ipdom[n] = best if best is not None else n

    return ipdom


# ---------------------------------------------------------------------------
# Identify exit nodes
# ---------------------------------------------------------------------------


def _find_exit_nodes(
    insn_successors: dict[int, set[int]],
    all_nodes: set[int],
) -> set[int]:
    """Return nodes with no successors in the original CFG."""
    exits = set()
    for n in all_nodes:
        if not insn_successors.get(n):
            exits.add(n)
    return exits


# ---------------------------------------------------------------------------
# Identify conditional branches
# ---------------------------------------------------------------------------


def _is_conditional_branch(
    insn_idx: int,
    insn_successors: dict[int, set[int]],
    insn_map: dict | None = None,
) -> bool:
    """Return True if insn_idx is a conditional branch.

    Primary check: the instruction has exactly 2 successors in the CFG (both
    arms were explored by the verifier).

    Fallback (partial CFG): if only 1 successor was explored but the instruction
    opcode is a branch and it is NOT an unconditional goto, we still treat it as
    a conditional branch.  This handles the common case where the verifier only
    explored one arm (e.g., `from 28 to 30` annotation with the fall-through
    path unexplored).
    """
    succs = insn_successors.get(insn_idx, set())
    if len(succs) == 2:
        return True
    if len(succs) == 1 and insn_map is not None:
        insn = insn_map.get(insn_idx)
        if insn is not None:
            info = _get_opcode_info(insn)
            if info is not None and info.is_branch:
                bytecode = insn.bytecode or ""
                if not is_unconditional_goto(bytecode):
                    return True
    return False


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------


def compute_control_dependence(
    cfg: "TraceCFG",
    insn_map: dict | None = None,
) -> ControlDep:
    """Compute control dependence from a TraceCFG.

    For each instruction B, ``result.deps[B]`` contains the set of branch
    instruction indices that B is control-dependent on.

    Algorithm (Cytron et al. §3):
      For each conditional branch A with successors {S1, S2}:
        For each Si:
          runner = Si
          while runner != ipdom[A]:
            deps[runner].add(A)
            runner = ipdom[runner]

    Parameters
    ----------
    cfg:
        The TraceCFG produced by ``build_cfg`` / ``build_cfg_from_trace``.
    insn_map:
        Optional mapping from instruction index to TracedInstruction.  When
        provided, enables opcode-based detection of conditional branches in
        partial CFGs where the verifier only explored one arm of a conditional.
        If ``None``, only branches with two explored successors are detected.

    Returns
    -------
    ControlDep
        The control dependence result.  ``result.ipdom`` exposes the immediate
        post-dominator map for inspection / testing.
    """
    insn_successors = cfg.insn_successors
    insn_predecessors = cfg.insn_predecessors
    all_nodes: set[int] = set(insn_successors.keys()) | set(insn_predecessors.keys())

    if not all_nodes:
        return ControlDep(deps={}, ipdom={})

    exit_nodes = _find_exit_nodes(insn_successors, all_nodes)

    # If there are no exit nodes (e.g., only a single instruction that was
    # truncated), treat all leaf nodes (no successors in insn_successors) as
    # exits.  If still empty, treat the last node as exit.
    if not exit_nodes:
        exit_nodes = {max(all_nodes)}

    ipdom_raw = _compute_postdom(
        insn_successors, insn_predecessors, all_nodes, exit_nodes
    )

    # Map _VIRT_EXIT -> keep as-is; for real nodes we use their entry in ipdom_raw.
    # Build a clean ipdom that only contains real instruction indices.
    ipdom: dict[int, int] = {}
    for n in all_nodes:
        raw = ipdom_raw.get(n, n)
        # If the immediate post-dominator is the virtual exit node, map it to
        # the node itself (the node post-dominates all other nodes, or there is
        # no real post-dominator — treat as self).
        ipdom[n] = raw if raw != _VIRT_EXIT else n

    # ------------------------------------------------------------------
    # Build control dependence graph.
    # ------------------------------------------------------------------
    deps: dict[int, set[int]] = {n: set() for n in all_nodes}

    for branch_idx in all_nodes:
        if not _is_conditional_branch(branch_idx, insn_successors, insn_map):
            # Only conditional branches create control dependence.
            continue

        succs = insn_successors.get(branch_idx, set())
        ipdom_branch = ipdom.get(branch_idx, branch_idx)

        if len(succs) == 2:
            # Full CFG case: both arms explored.
            # Walk up ipdom tree from each successor until reaching ipdom(branch).
            for succ in succs:
                runner = succ
                visited: set[int] = set()
                while runner != ipdom_branch and runner not in visited:
                    visited.add(runner)
                    deps.setdefault(runner, set()).add(branch_idx)
                    next_runner = ipdom.get(runner, runner)
                    if next_runner == runner:
                        break
                    runner = next_runner
        else:
            # Partial CFG case: only one arm was explored by the verifier.
            # The single explored arm is the path the verifier took.  Every
            # instruction reachable from the explored successor (and not the
            # branch itself) executed only because this branch went this way.
            # Mark all reachable instructions as control-dependent on branch_idx,
            # using BFS/DFS through insn_successors.
            for succ in succs:
                reachable: set[int] = set()
                worklist = [succ]
                while worklist:
                    node = worklist.pop()
                    if node in reachable or node == branch_idx:
                        continue
                    reachable.add(node)
                    for child in insn_successors.get(node, set()):
                        if child not in reachable:
                            worklist.append(child)
                for node in reachable:
                    deps.setdefault(node, set()).add(branch_idx)

    return ControlDep(deps=deps, ipdom=ipdom)


# ---------------------------------------------------------------------------
# Convenience: build from parsed trace
# ---------------------------------------------------------------------------


def compute_control_dependence_from_trace(parsed_trace) -> ControlDep:
    """Build the CFG and compute control dependence from a ParsedTrace.

    This is the preferred high-level entry point.  It automatically provides
    the ``insn_map`` so that conditional branches are detected by opcode even
    in partial CFGs where the verifier only explored one arm.

    Parameters
    ----------
    parsed_trace:
        A ``ParsedTrace`` object from ``bpfix.extractor.trace_parser``.

    Returns
    -------
    ControlDep
    """
    from .cfg_builder import build_cfg_from_trace

    cfg = build_cfg_from_trace(parsed_trace)
    # Build insn_map: idx → TracedInstruction (first occurrence)
    insn_map: dict[int, object] = {}
    for insn in parsed_trace.instructions:
        if insn.insn_idx not in insn_map:
            insn_map[insn.insn_idx] = insn
    return compute_control_dependence(cfg, insn_map=insn_map)


# ---------------------------------------------------------------------------
# Convenience query helpers
# ---------------------------------------------------------------------------


def controlling_branches(
    result: ControlDep,
    insn_idx: int,
) -> set[int]:
    """Return the set of branch instruction indices that *insn_idx* depends on.

    Returns an empty set if *insn_idx* is not control-dependent on any branch.
    """
    return set(result.deps.get(insn_idx, set()))


def control_dependent_instructions(
    result: ControlDep,
    branch_idx: int,
) -> set[int]:
    """Return the set of instruction indices that are control-dependent on
    *branch_idx*.

    This is the inverse of ``controlling_branches``.
    """
    return {insn for insn, branches in result.deps.items() if branch_idx in branches}
