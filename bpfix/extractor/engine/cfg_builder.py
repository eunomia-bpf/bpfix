"""CFG reconstruction from BPF verifier trace.

Builds a partial control flow graph from the verifier's explored instruction
sequence.  No keyword heuristics — analysis is driven by:
  1. Branch opcodes (JMP/JMP32 class — opcode & 0x07 in {0x05, 0x06})
  2. Branch targets extracted from bytecode disassembly ("goto pc+N" / "goto pc-N")
  3. Sequential fall-through for non-branch, non-exit instructions
  4. `from X to Y` annotations parsed from the verifier trace
  5. EXIT instructions (opcode 0x95) — terminal nodes

The resulting TraceCFG contains both an instruction-level view (successors/
predecessors per instruction index) and a basic-block view.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..trace_parser import TracedInstruction

from .opcode_safety import decode_opcode

# ---------------------------------------------------------------------------
# Regex for branch target extraction
# ---------------------------------------------------------------------------

# Matches "goto pc+N" or "goto pc-N" in BPF bytecode disassembly.
# The BPF verifier always uses "pc+N" or "pc-N" notation (no space after pc).
_BRANCH_TARGET_RE = re.compile(r"\bgoto\s+pc([+-]\d+)")

# Unconditional goto: starts with "goto pc..." with no "if" prefix.
_UNCONDITIONAL_GOTO_RE = re.compile(r"^\s*goto\s+pc[+-]")

# ld_imm64 opcode byte (0x18): occupies two instruction slots.
_LD_IMM64_OPCODE = 0x18

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class BasicBlock:
    """A basic block in the reconstructed CFG.

    ``start_idx`` and ``end_idx`` are BPF instruction indices.
    ``instructions`` holds the TracedInstruction objects whose insn_idx falls
    inside [start_idx, end_idx] in trace order.
    ``successors`` and ``predecessors`` hold the *start_idx* values of
    neighbouring blocks.
    """

    start_idx: int
    end_idx: int
    instructions: list  # list[TracedInstruction]
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)


@dataclass
class TraceCFG:
    """Partial control flow graph reconstructed from a verifier trace.

    All mappings use instruction indices (int) as keys/values.

    ``blocks`` maps block start_idx → BasicBlock.
    ``edges`` is the canonical list of (from_block_start, to_block_start) edges.
    ``entry`` is the start_idx of the entry block (first explored instruction).

    Instruction-level adjacency is also available via ``insn_successors`` and
    ``insn_predecessors`` for analyses that don't need basic blocks.
    """

    blocks: dict[int, BasicBlock]
    entry: int
    edges: list[tuple[int, int]]
    # Instruction-level adjacency
    insn_successors: dict[int, set[int]] = field(default_factory=dict)
    insn_predecessors: dict[int, set[int]] = field(default_factory=dict)

    # -----------------------------------------------------------------------
    # Helper methods matching the interface specified in the task description
    # -----------------------------------------------------------------------

    def get_block_for_insn(self, insn_idx: int) -> BasicBlock | None:
        """Return the BasicBlock that contains instruction ``insn_idx``."""
        for block in self.blocks.values():
            if block.start_idx <= insn_idx <= block.end_idx:
                return block
        return None

    def predecessors(self, block_start: int) -> list[int]:
        """Return start_idx values of predecessor blocks."""
        block = self.blocks.get(block_start)
        if block is None:
            return []
        return list(block.predecessors)

    def successors(self, block_start: int) -> list[int]:
        """Return start_idx values of successor blocks."""
        block = self.blocks.get(block_start)
        if block is None:
            return []
        return list(block.successors)


# ---------------------------------------------------------------------------
# Branch target extraction helpers
# ---------------------------------------------------------------------------


def extract_branch_target(bytecode: str, insn_idx: int) -> int | None:
    """Return the branch target instruction index, or None if not a branch.

    Handles both "if rX op rY goto pc+N" (conditional) and "goto pc+N"
    (unconditional).  The offset N may be positive or negative.
    """
    match = _BRANCH_TARGET_RE.search(bytecode)
    if match:
        offset = int(match.group(1))
        return insn_idx + offset + 1
    return None


def is_unconditional_goto(bytecode: str) -> bool:
    """Return True if this bytecode is an unconditional goto (no 'if' prefix)."""
    return bool(_UNCONDITIONAL_GOTO_RE.match(bytecode.strip()))


# ---------------------------------------------------------------------------
# Opcode classification helpers
# ---------------------------------------------------------------------------


def _get_opcode_info(insn: "TracedInstruction"):  # noqa: ANN201
    """Return OpcodeInfo for a TracedInstruction.

    Requires the stored opcode_hex emitted by the trace parser.
    """
    opcode_hex = getattr(insn, "opcode_hex", None)
    bytecode = insn.bytecode or ""
    if not opcode_hex:
        return None
    try:
        return decode_opcode(opcode_hex, bytecode)
    except (ValueError, TypeError):
        return None


def _is_ld_imm64(insn: "TracedInstruction") -> bool:
    """Return True if this is an ld_imm64 (opcode 0x18, two-slot instruction)."""
    opcode_hex = getattr(insn, "opcode_hex", None)
    if opcode_hex is not None:
        try:
            return int(opcode_hex, 16) == _LD_IMM64_OPCODE
        except (ValueError, TypeError):
            pass
    return False


# ---------------------------------------------------------------------------
# Core CFG builder
# ---------------------------------------------------------------------------


def build_cfg(traced_instructions: list) -> TraceCFG:
    """Build a partial CFG from a list of TracedInstruction objects.

    Algorithm overview
    ------------------
    1. Collect all instruction indices that appear in the trace.
    2. For each instruction determine its successor(s):
       - EXIT → no successors
       - CALL → fall-through to idx+1
       - Unconditional goto → single successor at branch target
       - Conditional branch → fall-through (idx+1) + branch target
       - ld_imm64 (0x18) → fall-through to idx+2 (two-slot instruction)
       - Everything else → fall-through to idx+1
    3. Augment with "from X to Y" edges from the verifier's DFS annotations.
       These are supplied via ParsedTrace.cfg_edges, but the caller may also
       pass a ``TracedInstruction`` list that carries a ``_cfg_edges`` attr,
       or supply the ``cfg_edges`` parameter explicitly.
    4. Identify basic-block leaders and build BasicBlock objects.

    The caller should pass any ``from X to Y`` edges separately or attach them
    to the instruction list as ``traced_instructions._cfg_edges``.
    The recommended entry point is ``build_cfg_from_trace(parsed_trace)``.
    """
    if not traced_instructions:
        return TraceCFG(
            blocks={},
            entry=0,
            edges=[],
            insn_successors={},
            insn_predecessors={},
        )

    # Deduplicate by insn_idx; the verifier may emit the same instruction
    # multiple times (explored under different abstract states on different paths).
    # We keep the *first* occurrence for instruction metadata.
    seen_idxs: set[int] = set()
    unique_insns: list = []
    for insn in traced_instructions:
        if insn.insn_idx not in seen_idxs:
            seen_idxs.add(insn.insn_idx)
            unique_insns.append(insn)

    insn_map: dict[int, object] = {insn.insn_idx: insn for insn in unique_insns}
    insn_set: set[int] = set(insn_map)

    # ------------------------------------------------------------------
    # Step 1: Collect extra CFG edges from ``from X to Y`` annotations.
    # ------------------------------------------------------------------
    extra_edges: list[tuple[int, int]] = []
    cfg_edges_attr = getattr(traced_instructions, "_cfg_edges", None)
    if cfg_edges_attr:
        extra_edges = list(cfg_edges_attr)

    # ------------------------------------------------------------------
    # Step 2: Determine successors for each instruction.
    # ------------------------------------------------------------------
    successors: dict[int, set[int]] = {idx: set() for idx in insn_set}
    branch_targets: dict[int, int] = {}  # insn_idx → explicit branch target

    for insn in unique_insns:
        idx = insn.insn_idx
        info = _get_opcode_info(insn)

        if info is None:
            # Fallback: sequential fall-through
            if idx + 1 in insn_set:
                successors[idx].add(idx + 1)
            continue

        if info.is_exit:
            # Terminal — no successors.
            pass

        elif info.is_call:
            # BPF_CALL returns to idx+1.
            fall = idx + 1
            if fall in insn_set:
                successors[idx].add(fall)

        elif info.is_branch:
            target = extract_branch_target(insn.bytecode, idx)
            if target is not None:
                branch_targets[idx] = target
                if is_unconditional_goto(insn.bytecode):
                    # Unconditional: single successor.
                    if target in insn_set:
                        successors[idx].add(target)
                else:
                    # Conditional: fall-through + branch target.
                    fall = idx + 1
                    if fall in insn_set:
                        successors[idx].add(fall)
                    if target in insn_set:
                        successors[idx].add(target)
            else:
                # Could not parse target; assume fall-through only.
                fall = idx + 1
                if fall in insn_set:
                    successors[idx].add(fall)

        elif _is_ld_imm64(insn):
            # ld_imm64 occupies two slots; fall-through to idx+2.
            fall = idx + 2
            if fall in insn_set:
                successors[idx].add(fall)
            elif idx + 1 in insn_set:
                # Second slot may be present in trace with same opcode;
                # treat as its own fall-through.
                successors[idx].add(idx + 1)

        else:
            # Sequential fall-through.
            fall = idx + 1
            if fall in insn_set:
                successors[idx].add(fall)

    # ------------------------------------------------------------------
    # Step 3: Augment with ``from X to Y`` edges.
    # ------------------------------------------------------------------
    for from_idx, to_idx in extra_edges:
        if from_idx not in successors:
            successors[from_idx] = set()
        if to_idx in insn_set or to_idx not in insn_set:
            # Add regardless — the annotation is authoritative.
            successors[from_idx].add(to_idx)
            if to_idx not in insn_set:
                insn_set.add(to_idx)
                successors[to_idx] = set()

    # ------------------------------------------------------------------
    # Step 4: Build predecessor map.
    # ------------------------------------------------------------------
    predecessors: dict[int, set[int]] = {idx: set() for idx in insn_set}
    for src, dsts in successors.items():
        for dst in dsts:
            if dst not in predecessors:
                predecessors[dst] = set()
            predecessors[dst].add(src)

    # ------------------------------------------------------------------
    # Step 5: Identify basic-block leaders.
    # ------------------------------------------------------------------
    sorted_insns = sorted(insn_set)
    entry_idx = sorted_insns[0]

    leaders: set[int] = {entry_idx}
    for idx in sorted_insns:
        succs = successors.get(idx, set())
        current_insn = insn_map.get(idx)
        is_two_slot = current_insn is not None and _is_ld_imm64(current_insn)

        if len(succs) > 1:
            # Branch instruction: each target starts a new block.
            leaders.update(succs)
        elif len(succs) == 1:
            (dst,) = succs
            # If successor is non-sequential, dst starts a new block.
            # (Sequential means dst == idx+1, or dst == idx+2 for ld_imm64.)
            is_sequential = dst == idx + 1 or (is_two_slot and dst == idx + 2)
            if not is_sequential:
                leaders.add(dst)
                # Also, the instruction after this one (fall-through)
                # starts a new block if it's in the trace.
                fall = idx + 1
                if fall in insn_set and fall != dst:
                    leaders.add(fall)
            else:
                preds_of_dst = predecessors.get(dst, set())
                if len(preds_of_dst) > 1:
                    # Merge point: the target starts a new block.
                    leaders.add(dst)
    # Also: any instruction with multiple predecessors starts a new block.
    for idx in sorted_insns:
        if len(predecessors.get(idx, set())) > 1:
            leaders.add(idx)

    # ------------------------------------------------------------------
    # Step 6: Build BasicBlock objects.
    # ------------------------------------------------------------------
    sorted_leaders = sorted(leaders)
    leader_set = set(sorted_leaders)
    blocks: dict[int, BasicBlock] = {}

    for i, leader in enumerate(sorted_leaders):
        # Collect instruction indices for this block: from leader until we hit
        # a block terminator or the next leader.
        block_insns_idxs: list[int] = []
        current = leader

        while True:
            if current in insn_set or current == leader:
                block_insns_idxs.append(current)
            else:
                break

            succs = successors.get(current, set())
            # Stop if:
            # (a) current has no successors (exit)
            # (b) current has multiple successors (branch)
            # (c) the single successor is not idx+1 (unconditional jump)
            # (d) next instruction is a leader
            if not succs:
                break
            if len(succs) > 1:
                break
            (next_idx,) = succs
            current_insn = insn_map.get(current)
            is_two_slot = current_insn is not None and _is_ld_imm64(current_insn)
            if next_idx == current + 1:
                # Normal sequential fall-through — continue in block.
                pass
            elif next_idx == current + 2 and is_two_slot:
                # ld_imm64 occupies two slots — also sequential.
                pass
            else:
                # Non-sequential (unconditional jump or branch): block ends here.
                break
            if next_idx in leader_set and next_idx != leader:
                # Next instruction is another block's leader.
                break
            current = next_idx

        block_insns: list = [
            insn_map[idx] for idx in block_insns_idxs if idx in insn_map
        ]
        start = block_insns_idxs[0] if block_insns_idxs else leader
        end = block_insns_idxs[-1] if block_insns_idxs else leader

        blocks[leader] = BasicBlock(
            start_idx=start,
            end_idx=end,
            instructions=block_insns,
            successors=[],   # filled below
            predecessors=[],  # filled below
        )

    # ------------------------------------------------------------------
    # Step 7: Build block-level edges.
    # ------------------------------------------------------------------
    block_edges: list[tuple[int, int]] = []

    def _block_of(insn_idx: int) -> int | None:
        """Return the start_idx of the block containing insn_idx."""
        for blk_start in sorted_leaders:
            blk = blocks[blk_start]
            if blk.start_idx <= insn_idx <= blk.end_idx:
                return blk_start
        return None

    for blk_start, blk in blocks.items():
        exit_insn_idx = blk.end_idx
        for succ_insn in successors.get(exit_insn_idx, set()):
            succ_blk = _block_of(succ_insn)
            if succ_blk is None:
                # Target not in a block (possibly unreached); skip.
                continue
            if succ_blk not in blk.successors:
                blk.successors.append(succ_blk)
            succ_block_obj = blocks[succ_blk]
            if blk_start not in succ_block_obj.predecessors:
                succ_block_obj.predecessors.append(blk_start)
            edge = (blk_start, succ_blk)
            if edge not in block_edges:
                block_edges.append(edge)

    return TraceCFG(
        blocks=blocks,
        entry=entry_idx,
        edges=block_edges,
        insn_successors=successors,
        insn_predecessors=predecessors,
    )


def build_cfg_from_trace(parsed_trace) -> TraceCFG:
    """Convenience wrapper: build a CFG from a ParsedTrace object.

    This is the preferred entry point.  It uses ``parsed_trace.instructions``
    and ``parsed_trace.cfg_edges`` (from-to annotations).
    """
    instructions = parsed_trace.instructions
    cfg_edges = getattr(parsed_trace, "cfg_edges", [])

    # Attach cfg_edges to the list so build_cfg can find them.
    # We use a thin wrapper to avoid mutating the original list.
    class _InsnList(list):
        pass

    insn_list = _InsnList(instructions)
    insn_list._cfg_edges = cfg_edges
    return build_cfg(insn_list)
