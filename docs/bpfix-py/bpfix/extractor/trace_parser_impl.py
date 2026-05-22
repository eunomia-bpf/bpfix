"""Parse LOG_LEVEL2 verifier state traces into instruction-level structures."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TypeAlias

from .shared_utils import is_pointer_type_name, normalize_register


INSTRUCTION_RE = re.compile(
    r"^\s*(?P<idx>\d+):\s*\((?P<opcode>[0-9a-fA-F]{2})\)\s*(?P<body>.*)$"
)
INSTRUCTION_FRAGMENT_RE = re.compile(
    r"(?<!\d)(?P<idx>\d+):\s*\((?P<opcode>[0-9a-fA-F]{2})\)\s*(?P<body>.*)$"
)
STATE_WITH_IDX_RE = re.compile(
    r"^\s*(?P<idx>\d+):\s*(?P<body>(?:frame\d+:\s*)?(?:[Rr]\d+|fp-?\d+).*)$"
)
STATE_FROM_TO_RE = re.compile(
    r"^\s*from\s+(?P<from_idx>\d+)\s+to\s+(?P<to_idx>\d+):\s*"
    r"(?P<body>(?:frame\d+:\s*)?(?:[Rr]\d+|fp-?\d+).*)$"
)
STATE_PLAIN_RE = re.compile(
    r"^\s*(?P<body>(?:frame\d+:\s*)?(?:[Rr]\d+|fp-?\d+).*)$"
)
BACKTRACK_SUMMARY_RE = re.compile(
    r"^\s*last_idx\s+(?P<last_idx>\d+)\s+first_idx\s+(?P<first_idx>\d+)\s*$"
)
BACKTRACK_DETAIL_RE = re.compile(
    r"^\s*regs=(?P<regs>\S+)\s+stack=(?P<stack>\S+)"
    r"(?:\s+before\s+(?P<before_idx>\d+):\s*(?P<before_insn>.*))?\s*$"
)
BACKTRACK_PARENT_RE = re.compile(
    r"^\s*parent didn't have regs=(?P<regs>\S+)\s+stack=(?P<stack>\S+)\s+marks\s*$",
    re.IGNORECASE,
)
TO_CALLER_RE = re.compile(r"^\s*to caller at\s+(?P<idx>\d+):\s*$", re.IGNORECASE)
VALIDATING_FUNC_RE = re.compile(r"^\s*Validating\b.*?\bfunc#(?P<func>\d+)\b", re.IGNORECASE)
STATE_TOKEN_RE = re.compile(
    r"(?P<key>(?:[Rr]\d+|fp-?\d+)(?:_[a-z]+)?)="
    r"(?P<value>.+?)(?=(?:\s+(?:[Rr]\d+|fp-?\d+)(?:_[a-z]+)?=)|$)"
)
ATTR_RE = re.compile(r"(?P<key>[a-zA-Z0-9_]+)=(?P<value>\([^)]*\)|[^,]+)")
REGISTER_REF_RE = re.compile(r"\b([rw])(\d+)\b")
INLINE_INSTRUCTION_ERROR_RE = re.compile(
    r":\s*(?P<error>(?:[Rr]\d+\s+)?(?:invalid|unbounded|offset is outside|pointer comparison prohibited|expected|must point|the prog does not allow).*)$",
    re.IGNORECASE,
)

ERROR_MARKERS = (
    "invalid access",
    "invalid mem access",
    "invalid bpf_context access",
    "offset is outside",
    "out of bounds",
    "not allowed",
    "unsupported",
    "unbounded",
    "pointer comparison prohibited",
    "failed to find kernel btf type id",
    "doesn't match number of subprogs",
    "invalid name",
    "permission denied",
    "math between",
    "reg type",
    "too many",
    "loop is not bounded",
    "bug",
    "warning",
)
@dataclass(slots=True)
class RegisterState:
    type: str
    id: int | None = None
    off: int | None = None
    range: int | None = None
    umin: int | None = None
    umax: int | None = None
    smin: int | None = None
    smax: int | None = None
    var_off: str | None = None


@dataclass(slots=True)
class InstructionLine:
    insn_idx: int
    opcode: str
    bytecode_text: str
    inline_error_text: str | None = None


@dataclass(slots=True)
class RegisterStateLine:
    registers: dict[str, RegisterState]


@dataclass(slots=True)
class SourceAnnotation:
    source_line: str


@dataclass(slots=True)
class BacktrackLine:
    last_idx: int | None = None
    first_idx: int | None = None
    regs: str | None = None
    stack: str | None = None
    before_idx: int | None = None
    before_insn: str | None = None


@dataclass(slots=True)
class ErrorLine:
    error_text: str


@dataclass(slots=True)
class OtherLine:
    text: str


TraceLine: TypeAlias = (
    InstructionLine
    | RegisterStateLine
    | SourceAnnotation
    | BacktrackLine
    | ErrorLine
    | OtherLine
)


@dataclass(slots=True)
class BacktrackInfo:
    last_idx: int | None = None
    first_idx: int | None = None
    regs: str | None = None
    stack: str | None = None
    lines: list[BacktrackLine] = field(default_factory=list)


@dataclass(slots=True)
class BacktrackLink:
    insn_idx: int
    bytecode: str
    regs: str
    stack: str


@dataclass(slots=True)
class BacktrackChain:
    error_insn: int
    first_insn: int
    links: list[BacktrackLink]
    regs_mask: str
    stack_mask: str


@dataclass(slots=True)
class TracedInstruction:
    insn_idx: int
    bytecode: str
    source_line: str | None
    pre_state: dict[str, RegisterState]
    post_state: dict[str, RegisterState]
    backtrack: BacktrackInfo | None
    is_error: bool
    error_text: str | None
    opcode_hex: str | None = None  # Raw opcode byte (e.g. "0f") from InstructionLine


@dataclass(slots=True)
class CriticalTransition:
    transition_type: str
    insn_idx: int
    register: str
    before: RegisterState
    after: RegisterState
    description: str


@dataclass(slots=True)
class ChainLink:
    insn_idx: int
    register: str
    state: RegisterState
    role: str
    description: str


@dataclass(slots=True)
class CausalChain:
    error_insn: int
    error_register: str
    error_description: str
    chain: list[ChainLink]


@dataclass(slots=True)
class ParsedTrace:
    instructions: list[TracedInstruction]
    critical_transitions: list[CriticalTransition]
    causal_chain: CausalChain | None
    backtrack_chains: list[BacktrackChain]
    error_line: str | None
    total_instructions: int
    has_btf_annotations: bool
    has_backtracking: bool
    validated_functions: list[int] = field(default_factory=list)
    caller_transfer_sites: list[int] = field(default_factory=list)
    cfg_edges: list[tuple[int, int]] = field(default_factory=list)  # from-to edges from verifier DFS


def parse_line(line: str) -> TraceLine:
    """Parse a single verifier-log line into a structured line type."""

    raw = _normalize_line(line.rstrip())
    stripped = raw.strip()
    if not stripped:
        return OtherLine(text="")
    error_candidate = stripped
    while error_candidate.startswith(":"):
        error_candidate = error_candidate[1:].lstrip()

    source_candidate = raw.lstrip()
    if source_candidate.startswith(":;"):
        source_candidate = source_candidate[1:].lstrip()
    if source_candidate.startswith(";"):
        return SourceAnnotation(source_line=source_candidate[1:].strip())

    backtrack_summary = BACKTRACK_SUMMARY_RE.match(raw)
    if backtrack_summary:
        return BacktrackLine(
            last_idx=int(backtrack_summary.group("last_idx")),
            first_idx=int(backtrack_summary.group("first_idx")),
        )

    backtrack_detail = BACKTRACK_DETAIL_RE.match(raw)
    if backtrack_detail:
        return BacktrackLine(
            regs=backtrack_detail.group("regs"),
            stack=backtrack_detail.group("stack"),
            before_idx=_parse_int(backtrack_detail.group("before_idx")),
            before_insn=(backtrack_detail.group("before_insn") or "").strip() or None,
        )

    instruction_text = _strip_instruction_wrapper(raw)
    instruction_match = INSTRUCTION_RE.match(instruction_text)
    if instruction_match:
        body_text, inline_error_text = _split_instruction_error_text(
            instruction_match.group("body")
        )
        bytecode = _strip_inline_comment(body_text).strip()
        return InstructionLine(
            insn_idx=int(instruction_match.group("idx")),
            opcode=instruction_match.group("opcode").lower(),
            bytecode_text=bytecode,
            inline_error_text=inline_error_text,
        )

    registers = _extract_registers_from_line(raw)
    if registers:
        return RegisterStateLine(registers=registers)

    if _looks_like_error(error_candidate):
        return ErrorLine(error_text=error_candidate)

    return OtherLine(text=stripped)


def parse_trace(log_text: str) -> ParsedTrace:
    """Parse a complete verifier verbose log into structured trace."""

    raw_lines = [line.rstrip() for line in log_text.splitlines() if line.strip()]
    instructions = _aggregate_instructions(raw_lines)
    transitions = _detect_critical_transitions(instructions)
    causal_chain = _extract_causal_chain(instructions)
    backtrack_chains = extract_backtrack_chains(log_text)
    error_texts = _collect_error_texts(instructions, raw_lines)
    validated_functions, caller_transfer_sites = _collect_validation_context(raw_lines)
    cfg_edges = _extract_cfg_edges(raw_lines)

    return ParsedTrace(
        instructions=instructions,
        critical_transitions=transitions,
        causal_chain=causal_chain,
        backtrack_chains=backtrack_chains,
        error_line=_select_error_line(error_texts),
        total_instructions=len(instructions),
        has_btf_annotations=any(instruction.source_line for instruction in instructions),
        has_backtracking=bool(backtrack_chains) or any(
            instruction.backtrack for instruction in instructions
        ),
        validated_functions=validated_functions,
        caller_transfer_sites=caller_transfer_sites,
        cfg_edges=cfg_edges,
    )


def parse_verifier_trace(log_text: str) -> ParsedTrace:
    """Backward-compatible alias used by corpus coverage scripts."""

    return parse_trace(log_text)


def _collect_validation_context(raw_lines: list[str]) -> tuple[list[int], list[int]]:
    validated_functions: list[int] = []
    caller_transfer_sites: list[int] = []

    for raw_line in raw_lines:
        normalized = _normalize_line(raw_line)
        func_match = VALIDATING_FUNC_RE.match(normalized)
        if func_match:
            validated_functions.append(int(func_match.group("func")))
            continue

        to_caller_match = TO_CALLER_RE.match(normalized)
        if to_caller_match:
            caller_transfer_sites.append(int(to_caller_match.group("idx")))

    return validated_functions, caller_transfer_sites


def extract_backtrack_chains(log_text: str) -> list[BacktrackChain]:
    """Extract structured verifier backtracking sequences from a raw verbose log."""

    chains: list[BacktrackChain] = []
    summary_last_idx: int | None = None
    summary_first_idx: int | None = None
    detail_lines: list[BacktrackLine] = []

    def flush_current_chain() -> None:
        nonlocal summary_last_idx, summary_first_idx, detail_lines
        if summary_last_idx is None or summary_first_idx is None or not detail_lines:
            summary_last_idx = None
            summary_first_idx = None
            detail_lines = []
            return

        links = [
            BacktrackLink(
                insn_idx=line.before_idx,
                bytecode=line.before_insn or "",
                regs=line.regs or "",
                stack=line.stack or "",
            )
            for line in detail_lines
            if line.before_idx is not None
        ]
        if not links:
            summary_last_idx = None
            summary_first_idx = None
            detail_lines = []
            return

        chains.append(
            BacktrackChain(
                error_insn=summary_last_idx,
                first_insn=summary_first_idx,
                links=links,
                regs_mask=detail_lines[0].regs or "",
                stack_mask=detail_lines[0].stack or "",
            )
        )
        summary_last_idx = None
        summary_first_idx = None
        detail_lines = []

    for raw_line in log_text.splitlines():
        normalized = _normalize_line(raw_line.rstrip())
        if not normalized.strip():
            continue

        parsed = parse_line(normalized)
        if isinstance(parsed, InstructionLine):
            continue

        if isinstance(parsed, BacktrackLine):
            if parsed.last_idx is not None and parsed.first_idx is not None:
                flush_current_chain()
                summary_last_idx = parsed.last_idx
                summary_first_idx = parsed.first_idx
                continue

            if summary_last_idx is None or summary_first_idx is None:
                continue
            detail_lines.append(parsed)
            continue

        if BACKTRACK_PARENT_RE.match(normalized):
            flush_current_chain()
            continue

        if summary_last_idx is not None and summary_first_idx is not None:
            flush_current_chain()

    flush_current_chain()
    return chains


def _aggregate_instructions(raw_lines: list[str]) -> list[TracedInstruction]:
    instructions: list[TracedInstruction] = []
    active_source: str | None = None
    pending_state_by_idx: dict[int, dict[str, RegisterState]] = {}
    pending_state: dict[str, RegisterState] | None = None
    pending_state_idx: int | None = None
    current: TracedInstruction | None = None

    for raw_line in raw_lines:
        normalized = _normalize_line(raw_line)
        parsed = parse_line(normalized)

        match parsed:
            case SourceAnnotation(source_line=source_line):
                # BTF annotations describe the current source statement and may cover
                # multiple subsequent instructions until the next annotation appears.
                active_source = source_line
            case RegisterStateLine(registers=registers):
                explicit_idx = _extract_state_idx(normalized)
                target_idx = explicit_idx if explicit_idx is not None else pending_state_idx

                if target_idx is not None:
                    existing = pending_state_by_idx.get(target_idx, {})
                    pending_state_by_idx[target_idx] = _merge_states(existing, registers)
                    if current and current.insn_idx < target_idx:
                        current.post_state = _merge_states(current.post_state, registers)
                    elif current and current.insn_idx == target_idx and not current.pre_state:
                        current.pre_state = _merge_states(current.pre_state, registers)
                else:
                    pending_state = _merge_states(pending_state or {}, registers)
                    if current:
                        current.post_state = _merge_states(current.post_state, registers)

                pending_state_idx = None
            case InstructionLine(
                insn_idx=insn_idx,
                opcode=opcode,
                bytecode_text=bytecode_text,
                inline_error_text=inline_error_text,
            ):
                pre_state = pending_state_by_idx.pop(insn_idx, {})
                if pending_state:
                    pre_state = _merge_states(pending_state, pre_state)
                    pending_state = None
                elif not pre_state and current and insn_idx >= current.insn_idx:
                    effective_state = _effective_state(current)
                    if effective_state:
                        pre_state = effective_state

                source_line = active_source

                instruction = TracedInstruction(
                    insn_idx=insn_idx,
                    bytecode=bytecode_text,
                    source_line=source_line,
                    pre_state=pre_state,
                    post_state={},
                    backtrack=None,
                    is_error=False,
                    error_text=None,
                    opcode_hex=opcode,
                )

                if current and pre_state:
                    current.post_state = _merge_states(current.post_state, pre_state)

                inline_comment = _extract_inline_comment(normalized)
                inline_registers = _extract_registers_from_text(inline_comment)
                if inline_registers:
                    instruction.post_state = _merge_states(instruction.post_state, inline_registers)
                elif inline_comment and not instruction.source_line and not _looks_like_error(inline_comment):
                    instruction.source_line = inline_comment
                if inline_error_text:
                    instruction.is_error = True
                    instruction.error_text = inline_error_text

                instructions.append(instruction)
                current = instruction
                pending_state_idx = None
            case BacktrackLine() as backtrack_line:
                if current is None:
                    continue
                if current.backtrack is None:
                    current.backtrack = BacktrackInfo()
                current.backtrack.lines.append(backtrack_line)
                if backtrack_line.last_idx is not None:
                    current.backtrack.last_idx = backtrack_line.last_idx
                if backtrack_line.first_idx is not None:
                    current.backtrack.first_idx = backtrack_line.first_idx
                if backtrack_line.regs is not None:
                    current.backtrack.regs = backtrack_line.regs
                if backtrack_line.stack is not None:
                    current.backtrack.stack = backtrack_line.stack
            case ErrorLine(error_text=error_text):
                if current is not None:
                    current.is_error = True
                    if current.error_text:
                        current.error_text = f"{current.error_text}\n{error_text}"
                    else:
                        current.error_text = error_text
            case OtherLine(text=text):
                to_caller_match = TO_CALLER_RE.match(text)
                if to_caller_match:
                    pending_state_idx = int(to_caller_match.group("idx"))

    return instructions


def _detect_critical_transitions(
    instructions: list[TracedInstruction],
) -> list[CriticalTransition]:
    transitions: list[CriticalTransition] = []

    for instruction in instructions:
        registers = {
            register
            for register in set(instruction.pre_state) | set(instruction.post_state)
            if register.startswith("R")
        }
        for register in sorted(registers):
            before = instruction.pre_state.get(register)
            after = instruction.post_state.get(register)
            if before is None or after is None or _same_state(before, after):
                continue

            if _is_bounds_collapse(before, after):
                transitions.append(
                    CriticalTransition(
                        transition_type="BOUNDS_COLLAPSE",
                        insn_idx=instruction.insn_idx,
                        register=register,
                        before=before,
                        after=after,
                        description=(
                            f"{register} lost scalar bounds at insn {instruction.insn_idx}: "
                            f"{_describe_state(before)} -> {_describe_state(after)}"
                        ),
                    )
                )

            if _is_type_downgrade(before, after):
                transitions.append(
                    CriticalTransition(
                        transition_type="TYPE_DOWNGRADE",
                        insn_idx=instruction.insn_idx,
                        register=register,
                        before=before,
                        after=after,
                        description=(
                            f"{register} downgraded from pointer-like {before.type} to {after.type} "
                            f"at insn {instruction.insn_idx}"
                        ),
                    )
                )

            if _is_provenance_loss(before, after):
                transitions.append(
                    CriticalTransition(
                        transition_type="PROVENANCE_LOSS",
                        insn_idx=instruction.insn_idx,
                        register=register,
                        before=before,
                        after=after,
                        description=(
                            f"{register} lost tracked provenance at insn {instruction.insn_idx}: "
                            f"{_describe_state(before)} -> {_describe_state(after)}"
                        ),
                    )
                )

            if _is_range_loss(before, after):
                transitions.append(
                    CriticalTransition(
                        transition_type="RANGE_LOSS",
                        insn_idx=instruction.insn_idx,
                        register=register,
                        before=before,
                        after=after,
                        description=(
                            f"{register} lost packet range proof at insn {instruction.insn_idx}: "
                            f"r={before.range} -> r={after.range}"
                        ),
                    )
                )

    return transitions


def _extract_causal_chain(instructions: list[TracedInstruction]) -> CausalChain | None:
    error_position = next(
        (idx for idx in range(len(instructions) - 1, -1, -1) if instructions[idx].is_error),
        None,
    )
    if error_position is None:
        return None

    error_instruction = instructions[error_position]
    error_text = error_instruction.error_text or ""
    error_register = _extract_error_register(error_text)
    if error_register is None:
        return None

    error_state = (
        error_instruction.pre_state.get(error_register)
        or error_instruction.post_state.get(error_register)
    )
    if error_state is None:
        return None

    links = _trace_register_chain(
        instructions,
        position=error_position,
        register=error_register,
        target_state=error_state,
        visited=set(),
        depth=0,
    )

    chain = _dedupe_chain_links(links)
    if chain:
        chain[0].role = "root_cause"
        for link in chain[1:]:
            link.role = "propagation"

    chain.append(
        ChainLink(
            insn_idx=error_instruction.insn_idx,
            register=error_register,
            state=error_state,
            role="error_site",
            description=error_text.splitlines()[0] if error_text else "verifier rejected access",
        )
    )

    return CausalChain(
        error_insn=error_instruction.insn_idx,
        error_register=error_register,
        error_description=error_text,
        chain=chain,
    )


def _trace_register_chain(
    instructions: list[TracedInstruction],
    position: int,
    register: str,
    target_state: RegisterState,
    visited: set[tuple[int, str]],
    depth: int,
) -> list[ChainLink]:
    if depth >= 5:
        return []

    search_key = (position, register)
    if search_key in visited:
        return []
    visited.add(search_key)

    candidate_position = _find_previous_definition(
        instructions, position=position, register=register, target_state=target_state
    )
    if candidate_position is None:
        return []

    candidate = instructions[candidate_position]
    candidate_state = (
        candidate.post_state.get(register)
        or candidate.pre_state.get(register)
        or target_state
    )

    links: list[ChainLink] = []
    source_registers = _extract_source_registers(candidate.bytecode, register)
    for source_register in source_registers:
        source_state = (
            candidate.pre_state.get(source_register)
            or candidate.post_state.get(source_register)
            or candidate_state
        )
        links.extend(
            _trace_register_chain(
                instructions,
                position=candidate_position,
                register=source_register,
                target_state=source_state,
                visited=visited,
                depth=depth + 1,
            )
        )

    links.append(
        ChainLink(
            insn_idx=candidate.insn_idx,
            register=register,
            state=candidate_state,
            role="propagation",
            description=_describe_chain_step(candidate, register, candidate_state),
        )
    )
    return links


def _find_previous_definition(
    instructions: list[TracedInstruction],
    position: int,
    register: str,
    target_state: RegisterState,
) -> int | None:
    for idx in range(position - 1, -1, -1):
        instruction = instructions[idx]
        post_state = instruction.post_state.get(register)
        if post_state and _states_related(post_state, target_state):
            if register in _extract_destination_registers(instruction.bytecode) or _state_changed(
                instruction, register
            ):
                return idx

    return None


def _extract_destination_registers(bytecode: str) -> set[str]:
    text = bytecode.strip().lower()
    if text.startswith("call "):
        return {"R0"}

    match = re.match(r"^(?P<reg>[rw]\d+)\s*(?:=|\+=|-=|\*=|/=|<<=|>>=|&=|\|=|\^=)", text)
    if match:
        return {_normalize_register_name(match.group("reg"))}
    return set()


def _extract_source_registers(bytecode: str, target_register: str) -> list[str]:
    text = bytecode.strip().lower()
    if text.startswith("call "):
        return []

    destination_match = re.match(
        r"^(?P<reg>[rw]\d+)\s*(?P<op>=|\+=|-=|\*=|/=|<<=|>>=|&=|\|=|\^=)\s*(?P<rhs>.*)$",
        text,
    )
    if destination_match:
        rhs = destination_match.group("rhs")
        if destination_match.group("op") != "=":
            rhs = f"{destination_match.group('reg')} {rhs}"
    else:
        rhs = text

    registers: list[str] = []
    for match in REGISTER_REF_RE.finditer(rhs):
        normalized = _normalize_register_name(match.group(0))
        if normalized == target_register and not registers:
            continue
        if normalized not in registers:
            registers.append(normalized)
    return registers


def _state_changed(instruction: TracedInstruction, register: str) -> bool:
    before = instruction.pre_state.get(register)
    after = instruction.post_state.get(register)
    return before is not None and after is not None and not _same_state(before, after)


def _same_state(left: RegisterState, right: RegisterState) -> bool:
    return (
        left.type,
        left.id,
        left.off,
        left.range,
        left.umin,
        left.umax,
        left.smin,
        left.smax,
        left.var_off,
    ) == (
        right.type,
        right.id,
        right.off,
        right.range,
        right.umin,
        right.umax,
        right.smin,
        right.smax,
        right.var_off,
    )


def _states_related(left: RegisterState, right: RegisterState) -> bool:
    return (
        left.type == right.type
        and left.id == right.id
        and left.off == right.off
        and left.range == right.range
    )


def _is_bounds_collapse(before: RegisterState, after: RegisterState) -> bool:
    if not (_is_scalar_like(before) and _is_scalar_like(after)):
        return False
    if before.umax is not None and after.umax is None:
        return True
    if before.umin is not None and after.umin is None:
        return True
    if before.smin is not None and after.smin is None:
        return True
    if before.smax is not None and after.smax is None:
        return True
    if before.umax is not None and after.umax is not None:
        if after.umax > before.umax and (after.umax - before.umax) > max(255, before.umax):
            return True
    return False


def _is_type_downgrade(before: RegisterState, after: RegisterState) -> bool:
    return _is_pointer_type(before.type) and _is_scalar_like(after)


def _is_provenance_loss(before: RegisterState, after: RegisterState) -> bool:
    if not _is_pointer_type(before.type):
        return False
    if _is_scalar_like(after):
        return True
    return before.id is not None and after.id is None


def _is_range_loss(before: RegisterState, after: RegisterState) -> bool:
    return (
        _is_pointer_type(before.type)
        and _is_pointer_type(after.type)
        and (before.range or 0) > 0
        and (after.range or 0) == 0
    )


def _is_pointer_type(state_type: str) -> bool:
    return is_pointer_type_name(state_type)


def _is_scalar_like(state: RegisterState) -> bool:
    lowered = state.type.lower()
    return (
        lowered.startswith("inv")
        or lowered.startswith("scalar")
        or lowered == "unknown"
    )


def _extract_registers_from_line(line: str) -> dict[str, RegisterState]:
    body = _extract_state_body(line)
    if body is None:
        return {}
    return _extract_registers_from_text(body)


def _extract_registers_from_text(text: str | None) -> dict[str, RegisterState]:
    if not text:
        return {}

    registers: dict[str, RegisterState] = {}
    for match in STATE_TOKEN_RE.finditer(text.strip()):
        key = _normalize_state_key(match.group("key"))
        registers[key] = _parse_register_state(match.group("value").strip())
    return registers


def _extract_state_body(line: str) -> str | None:
    if INSTRUCTION_RE.match(_strip_instruction_wrapper(line)):
        return None

    for pattern in (STATE_FROM_TO_RE, STATE_WITH_IDX_RE, STATE_PLAIN_RE):
        match = pattern.match(line)
        if not match:
            continue
        body = match.group("body")
        if STATE_TOKEN_RE.search(body):
            return body
    return None


def _extract_state_idx(line: str) -> int | None:
    match = STATE_FROM_TO_RE.match(line)
    if match:
        return int(match.group("to_idx"))

    match = STATE_WITH_IDX_RE.match(line)
    if match and STATE_TOKEN_RE.search(match.group("body")):
        return int(match.group("idx"))

    return None


def _parse_register_state(value: str) -> RegisterState:
    state = RegisterState(type="unknown")
    match = re.match(r"^(?P<type>[a-zA-Z_][a-zA-Z0-9_]*)\((?P<attrs>.*)\)$", value)
    if match:
        state.type = match.group("type")
        _populate_state_attrs(state, match.group("attrs"))
        return state

    fp_match = re.match(r"^(fp)(?P<off>-?\d+)$", value)
    if fp_match:
        state.type = "fp"
        state.off = int(fp_match.group("off"))
        return state

    inv_match = re.match(r"^(?P<type>invP|inv)(?P<num>-?(?:0x[0-9a-fA-F]+|\d+))$", value)
    if inv_match:
        constant = _parse_int(inv_match.group("num"))
        state.type = inv_match.group("type")
        state.umin = constant
        state.umax = constant
        state.smin = constant
        state.smax = constant
        return state

    constant = _parse_int(value)
    if constant is not None:
        state.type = "scalar"
        state.umin = constant
        state.umax = constant
        state.smin = constant
        state.smax = constant
        return state

    type_match = re.match(r"^(?P<type>[a-zA-Z_][a-zA-Z0-9_]*)", value)
    if type_match:
        state.type = type_match.group("type")
    else:
        state.type = value or "unknown"
    return state


def _populate_state_attrs(state: RegisterState, attrs_text: str) -> None:
    attr_map = {
        "id": "id",
        "off": "off",
        "r": "range",
        "umin": "umin",
        "umin_value": "umin",
        "u32_min_value": "umin",
        "umax": "umax",
        "umax_value": "umax",
        "u32_max_value": "umax",
        "smin": "smin",
        "smin_value": "smin",
        "s32_min_value": "smin",
        "smax": "smax",
        "smax_value": "smax",
        "s32_max_value": "smax",
    }

    for match in ATTR_RE.finditer(attrs_text):
        key = match.group("key")
        value = match.group("value").strip()
        if key == "var_off":
            state.var_off = value
            continue

        field_name = attr_map.get(key)
        if field_name is None:
            continue

        parsed_value = _parse_int(value)
        if parsed_value is not None:
            setattr(state, field_name, parsed_value)


def _normalize_state_key(key: str) -> str:
    base = key.split("_", 1)[0]
    if base.lower().startswith("r"):
        return f"R{base[1:]}"
    return base


def _normalize_register_name(register: str) -> str:
    return normalize_register(register)


def _extract_inline_comment(line: str) -> str | None:
    if ";" not in line:
        return None
    comment = line.split(";", 1)[1].strip()
    return comment or None


def _strip_inline_comment(text: str) -> str:
    return text.split(";", 1)[0]


def _normalize_line(line: str) -> str:
    normalized = line.rstrip()
    while True:
        stripped = normalized.lstrip()
        if not stripped.startswith(">"):
            break
        stripped = stripped[1:]
        normalized = stripped.lstrip()
    return normalized.replace("\t", "    ")


_FROM_TO_RE = re.compile(r"^\s*from\s+(?P<from_idx>\d+)\s+to\s+(?P<to_idx>\d+):")


def _extract_cfg_edges(raw_lines: list[str]) -> list[tuple[int, int]]:
    """Extract 'from X to Y' CFG edges from raw verifier log lines."""
    edges: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for raw_line in raw_lines:
        normalized = _normalize_line(raw_line)
        match = _FROM_TO_RE.match(normalized)
        if match:
            from_idx = int(match.group("from_idx"))
            to_idx = int(match.group("to_idx"))
            edge = (from_idx, to_idx)
            if edge not in seen:
                seen.add(edge)
                edges.append(edge)
    return edges


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _merge_states(
    base: dict[str, RegisterState], update: dict[str, RegisterState]
) -> dict[str, RegisterState]:
    merged = dict(base)
    merged.update(update)
    return merged


def _effective_state(instruction: TracedInstruction) -> dict[str, RegisterState]:
    return _merge_states(instruction.pre_state, instruction.post_state)


def _looks_like_error(text: str) -> bool:
    lowered = text.lower()
    if lowered.startswith(("processed ", "max_states", "peak_states", "-- end", "validating ")):
        return False
    return any(marker in lowered for marker in ERROR_MARKERS)


def _collect_error_texts(
    instructions: list[TracedInstruction], raw_lines: list[str]
) -> list[str]:
    error_texts: list[str] = []
    for instruction in instructions:
        if not instruction.error_text:
            continue
        error_texts.extend(
            line.strip() for line in instruction.error_text.splitlines() if line.strip()
        )

    if error_texts:
        return error_texts

    for raw_line in raw_lines:
        parsed = parse_line(raw_line)
        if isinstance(parsed, ErrorLine):
            error_texts.append(parsed.error_text)
    return error_texts


def _select_error_line(error_texts: list[str]) -> str | None:
    if not error_texts:
        return None

    best_line = error_texts[-1]
    best_score = -1
    for line in error_texts:
        lowered = line.lower()
        score = 0
        if "invalid" in lowered:
            score += 5
        if "invalid bpf_context access" in lowered or "pointer comparison prohibited" in lowered:
            score += 5
        if "failed to find kernel btf type id" in lowered or "invalid name" in lowered:
            score += 5
        if "outside of the packet" in lowered or "out of bounds" in lowered:
            score += 4
        if "not allowed" in lowered or "unsupported" in lowered:
            score += 4
        if re.search(r"R\d+\(", line):
            score += 3
        if "off=" in lowered or "size=" in lowered:
            score += 2
        if lowered.startswith(("verifier error:", "permission denied", "prog section ")):
            score -= 4
        if lowered.startswith("processed "):
            score -= 6
        if score >= best_score:
            best_score = score
            best_line = line
    return best_line


def _extract_error_register(error_text: str) -> str | None:
    match = re.search(r"\b(R\d+)\b", error_text)
    if match:
        return match.group(1)
    return None


def _describe_state(state: RegisterState) -> str:
    parts = [state.type]
    if state.id is not None:
        parts.append(f"id={state.id}")
    if state.off is not None:
        parts.append(f"off={state.off}")
    if state.range is not None:
        parts.append(f"r={state.range}")
    if state.umax is not None:
        parts.append(f"umax={state.umax}")
    if state.var_off is not None:
        parts.append(f"var_off={state.var_off}")
    return ",".join(parts)


def _describe_chain_step(
    instruction: TracedInstruction, register: str, state: RegisterState
) -> str:
    if register in _extract_destination_registers(instruction.bytecode):
        return (
            f"{register} was updated by `{instruction.bytecode}` and became "
            f"{_describe_state(state)}"
        )
    return f"{register} still carried {_describe_state(state)} at `{instruction.bytecode}`"


def _dedupe_chain_links(links: list[ChainLink]) -> list[ChainLink]:
    deduped: list[ChainLink] = []
    seen: set[tuple[int, str]] = set()
    for link in links:
        key = (link.insn_idx, link.register)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(link)
    return deduped


def _strip_instruction_wrapper(line: str) -> str:
    match = INSTRUCTION_FRAGMENT_RE.search(line)
    if match is None or match.start() == 0:
        return line
    return line[match.start() :]


def _split_instruction_error_text(body: str) -> tuple[str, str | None]:
    match = INLINE_INSTRUCTION_ERROR_RE.search(body)
    if match is None:
        return body, None

    bytecode = body[: match.start()].rstrip()
    error_text = match.group("error").strip()
    return bytecode, error_text or None
