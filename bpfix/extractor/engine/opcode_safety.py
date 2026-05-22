"""Opcode-driven safety condition inference from BPF ISA semantics.

No keyword matching. No regex on error messages.
Safety conditions derived entirely from the BPF instruction opcode byte.

The BPF opcode byte has the following structure:
  7  6  5  4  3  2  1  0
 [    op    ][ src][class]

The class (bits 2:0) determines the instruction type and its safety domain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..shared_utils import is_pointer_type_name, is_nullable_pointer_type
from .helper_signatures import (
    get_helper_id_by_name,
    get_helper_signature,
    get_helper_safety_condition,
    get_helper_safety_conditions,
)


class OperandRole(Enum):
    BASE_PTR = "base_ptr"
    OFFSET_SCALAR = "offset_scalar"
    HELPER_ARG = "helper_arg"
    RETURN_VALUE = "return_value"
    REF_OBJECT = "ref_object"


@dataclass(frozen=True)
class SafetySchema:
    domain: SafetyDomain
    role: OperandRole
    access_size: int | None = None
    pointer_kind: str | None = None
    expected_types: tuple[str, ...] = ()
    allow_null: bool = False
    requires_range: bool = False
    requires_writable: bool = False
    helper_id: int | None = None
    helper_name: str | None = None
    helper_arg_index: int | None = None
    constraint: str | None = None


@dataclass(frozen=True)
class CarrierSpec:
    register: str
    role: OperandRole
    pointer_kind: str | None
    provenance_id: int | None
    reject_type: str | None
    is_primary: bool = False


# ---------------------------------------------------------------------------
# BPF opcode class constants (bits 2:0 of opcode byte)
# ---------------------------------------------------------------------------

BPF_LD    = 0x00  # Special loads (LD_IMM64, LD_ABS/IND)
BPF_LDX   = 0x01  # Memory load from [src_reg + off]
BPF_ST    = 0x02  # Memory store immediate to [dst_reg + off]
BPF_STX   = 0x03  # Memory store register to [dst_reg + off]
BPF_ALU   = 0x04  # 32-bit arithmetic/logic
BPF_JMP   = 0x05  # 64-bit jumps, calls, and exits
BPF_JMP32 = 0x06  # 32-bit jumps
BPF_ALU64 = 0x07  # 64-bit arithmetic/logic

# Special opcode bytes
BPF_CALL = 0x85   # JMP | CALL
BPF_EXIT = 0x95   # JMP | EXIT

# Memory access size encoding (bits 4:3)
_SIZE_MAP = {0x00: 4, 0x08: 2, 0x10: 1, 0x18: 8}
_UNKNOWN_NUMERIC_GAP = 1 << 62


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class OpcodeClass(Enum):
    LD     = 0
    LDX    = 1
    ST     = 2
    STX    = 3
    ALU    = 4
    JMP    = 5
    JMP32  = 6
    ALU64  = 7


class SafetyDomain(Enum):
    """The abstract domain in which the safety condition lives."""
    MEMORY_BOUNDS      = "memory_bounds"      # off + size <= range
    POINTER_TYPE       = "pointer_type"       # register must be a valid pointer
    SCALAR_BOUND       = "scalar_bound"       # scalar must have bounded umax
    NULL_SAFETY        = "null_safety"        # pointer must not be ptr_or_null
    REFERENCE_BALANCE  = "ref_balance"        # all refs released at exit
    ARG_CONTRACT       = "arg_contract"       # helper/kfunc argument types
    WRITE_PERMISSION   = "write_permission"   # target must be writable
    ARITHMETIC_LEGALITY = "arith_legality"   # pointer arithmetic allowed?


@dataclass(frozen=True)
class SafetyCondition:
    """A single safety condition derived from an opcode."""
    domain: SafetyDomain
    critical_register: str       # Which register must satisfy this condition
    required_property: str       # Human-readable description of what's required
    access_size: int | None = None   # For memory access conditions
    expected_types: tuple[str, ...] = ()
    allow_null: bool = False
    requires_range: bool = False
    requires_writable: bool = False
    helper_id: int | None = None
    helper_name: str | None = None
    constraint: str | None = None


@dataclass(frozen=True)
class OpcodeInfo:
    """Decoded opcode information."""
    raw: int                      # The raw opcode byte as an integer
    opclass: OpcodeClass          # Instruction class
    is_memory_access: bool        # True for LDX/ST/STX
    is_call: bool                 # True for CALL (0x85)
    is_exit: bool                 # True for EXIT (0x95)
    is_alu: bool                  # True for ALU/ALU64
    is_branch: bool               # True for conditional branches
    access_size: int | None       # For memory ops: 1/2/4/8 bytes
    src_reg: str | None           # Decoded from bytecode text (e.g. "R1")
    dst_reg: str | None           # Decoded from bytecode text (e.g. "R3")
    call_target: str | None = None
    helper_id: int | None = None


# ---------------------------------------------------------------------------
# Register extraction from bytecode text
# ---------------------------------------------------------------------------

# Patterns to extract src/dst registers from verifier bytecode text.
# Examples:
#   "r6 = *(u8 *)(r0 +2)"   -> dst=R6, src=R0
#   "*(u64 *)(r10 -8) = r1" -> dst=R10, src=R1
#   "r0 |= r6"              -> dst=R0, src=R6
#   "r5 += r0"              -> dst=R5, src=R0
#   "call bpf_map_lookup_elem" -> no regs
_LOAD_RE = re.compile(
    r"^\s*(?P<dst>[rw]\d+)\s*=\s*\*\([^\)]+\)\s*\(\s*(?P<src>[rw]\d+)",
    re.IGNORECASE,
)
_STORE_REG_RE = re.compile(
    r"^\s*\*\([^\)]+\)\s*\(\s*(?P<dst>[rw]\d+)[^)]*\)\s*=\s*(?P<src>[rw]\d+)",
    re.IGNORECASE,
)
_STORE_IMM_RE = re.compile(
    r"^\s*\*\([^\)]+\)\s*\(\s*(?P<dst>[rw]\d+)",
    re.IGNORECASE,
)
_ALU_RE = re.compile(
    r"^\s*(?P<dst>[rw]\d+)\s*(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|>>>=|=)\s*(?P<src>[rw]\d+)?",
    re.IGNORECASE,
)
_CALL_TARGET_RE = re.compile(
    r"^\s*call\s+(?:(?P<pc>pc[+-]\d+)|(?P<name>[a-zA-Z0-9_]+)(?:#(?P<helper_id>\d+))?|#(?P<imm>\d+))",
    re.IGNORECASE,
)


def _normalize_reg(r: str | None) -> str | None:
    """Normalize a register token like 'r3' or 'w3' to 'R3'."""
    if r is None:
        return None
    m = re.match(r"^[rwRW](\d+)$", r.strip())
    if m:
        return f"R{m.group(1)}"
    return None


def _extract_regs_from_bytecode(bytecode: str) -> tuple[str | None, str | None]:
    """Extract (src_reg, dst_reg) from a verifier bytecode text line.

    Returns (src, dst) as normalized register names (e.g. 'R0', 'R3').
    Either may be None if not extractable.
    """
    if not bytecode:
        return None, None

    text = bytecode.strip()

    # Memory load: dst = *(uN *)(src + off)
    m = _LOAD_RE.match(text)
    if m:
        return _normalize_reg(m.group("src")), _normalize_reg(m.group("dst"))

    # Memory store register: *(uN *)(dst + off) = src
    m = _STORE_REG_RE.match(text)
    if m:
        return _normalize_reg(m.group("src")), _normalize_reg(m.group("dst"))

    # Memory store immediate: *(uN *)(dst + off) = imm
    m = _STORE_IMM_RE.match(text)
    if m:
        return None, _normalize_reg(m.group("dst"))

    # ALU / assignment: dst op= src  or  dst = src
    m = _ALU_RE.match(text)
    if m:
        dst = _normalize_reg(m.group("dst"))
        src = _normalize_reg(m.group("src")) if m.group("src") else None
        return src, dst

    return None, None

# ---------------------------------------------------------------------------
# Opcode decoder
# ---------------------------------------------------------------------------

def decode_opcode(hex_str: str, bytecode_text: str) -> OpcodeInfo:
    """Decode a 2-hex-digit opcode byte plus bytecode text into OpcodeInfo.

    Args:
        hex_str: The 2-character hex opcode string parsed from the verifier log
                 (e.g., "71" for LDX byte, "4f" for ALU64 OR).
        bytecode_text: The human-readable bytecode text (e.g., "r6 = *(u8 *)(r0 +2)").

    Returns:
        OpcodeInfo with all decoded fields.
    """
    raw = int(hex_str, 16)
    opclass = OpcodeClass(raw & 0x07)

    is_memory = opclass in (OpcodeClass.LDX, OpcodeClass.ST, OpcodeClass.STX)
    is_call = (raw == BPF_CALL)
    is_exit = (raw == BPF_EXIT)
    is_alu = opclass in (OpcodeClass.ALU, OpcodeClass.ALU64)
    is_branch = (
        opclass in (OpcodeClass.JMP, OpcodeClass.JMP32)
        and not is_call
        and not is_exit
    )

    access_size: int | None = None
    if is_memory:
        size_bits = (raw >> 3) & 0x03
        access_size = _SIZE_MAP.get(size_bits << 3)

    src_reg, dst_reg = _extract_regs_from_bytecode(bytecode_text)
    call_target, helper_id = _extract_call_target(bytecode_text) if is_call else (None, None)

    return OpcodeInfo(
        raw=raw,
        opclass=opclass,
        is_memory_access=is_memory,
        is_call=is_call,
        is_exit=is_exit,
        is_alu=is_alu,
        is_branch=is_branch,
        access_size=access_size,
        src_reg=src_reg,
        dst_reg=dst_reg,
        call_target=call_target,
        helper_id=helper_id,
    )


# ---------------------------------------------------------------------------
# Safety condition derivation (ISA-driven, zero keyword matching)
# ---------------------------------------------------------------------------

def derive_safety_conditions(
    info: OpcodeInfo,
    error_register: str | None = None,
) -> list[SafetyCondition]:
    """Derive all safety conditions implied by the opcode class.

    This is the ISA-derived mapping: opcode class -> safety domain.
    No error message parsing. No keyword heuristics.
    """
    conditions: list[SafetyCondition] = []

    if info.opclass == OpcodeClass.LDX:
        # Memory load: dst = *(uN *)(src + off)
        # Safety: src_reg must be a valid, non-null pointer with sufficient range.
        base = info.src_reg or "R?"
        conditions.append(SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register=base,
            required_property="must be a valid, non-scalar pointer type",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.NULL_SAFETY,
            critical_register=base,
            required_property="must not be ptr_or_null (null check required before dereference)",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.MEMORY_BOUNDS,
            critical_register=base,
            required_property=f"off + {info.access_size or '?'} <= range",
            access_size=info.access_size,
        ))

    elif info.opclass in (OpcodeClass.ST, OpcodeClass.STX):
        # Memory store: *(uN *)(dst + off) = src  or  *(uN *)(dst + off) = imm
        # Safety: dst_reg must be a valid, non-null, writable pointer.
        base = info.dst_reg or "R?"
        conditions.append(SafetyCondition(
            domain=SafetyDomain.POINTER_TYPE,
            critical_register=base,
            required_property="must be a valid, non-null, writable pointer type",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.NULL_SAFETY,
            critical_register=base,
            required_property="must not be ptr_or_null (null check required before store)",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.MEMORY_BOUNDS,
            critical_register=base,
            required_property=f"off + {info.access_size or '?'} <= range",
            access_size=info.access_size,
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.WRITE_PERMISSION,
            critical_register=base,
            required_property="pointee must be writable (not rdonly_mem or read-only packet data)",
        ))

    elif info.is_alu:
        # ALU / ALU64: dst op= src  or  dst op= imm
        # Safety depends on whether dst is a pointer (pointer arithmetic case) or scalar.
        dst = info.dst_reg or "R?"
        src = info.src_reg

        # If dst is a pointer, arithmetic legality applies.
        conditions.append(SafetyCondition(
            domain=SafetyDomain.ARITHMETIC_LEGALITY,
            critical_register=dst,
            required_property="if pointer, arithmetic must be legal for this pointer type (pkt/map_value/fp allow it; ctx/sock prohibit it)",
        ))
        # If src is a register and dst is a pointer, src (scalar) must be bounded.
        if src is not None:
            conditions.append(SafetyCondition(
                domain=SafetyDomain.SCALAR_BOUND,
                critical_register=src,
                required_property="if adding to a pointer, scalar must have known unsigned bounds (umax < 2^32)",
            ))

    elif info.is_call:
        if info.helper_id is not None:
            signature = get_helper_signature(info.helper_id)
            if signature is not None and error_register is not None:
                specific = get_helper_safety_condition(info.helper_id, error_register)
                if specific is not None:
                    return [specific]

            if signature is not None:
                helper_conditions = get_helper_safety_conditions(info.helper_id)
                return helper_conditions

        # Fallback for subprogram calls / unknown helpers.
        for i in range(1, 6):
            conditions.append(SafetyCondition(
                domain=SafetyDomain.ARG_CONTRACT,
                critical_register=f"R{i}",
                required_property="must match the helper/kfunc prototype (correct type and bounds)",
            ))

    elif info.is_exit:
        # EXIT: all acquired references must be released; R0 must satisfy return contract.
        conditions.append(SafetyCondition(
            domain=SafetyDomain.REFERENCE_BALANCE,
            critical_register="R0",
            required_property="all acquired references must be released before exit",
        ))
        conditions.append(SafetyCondition(
            domain=SafetyDomain.SCALAR_BOUND,
            critical_register="R0",
            required_property="R0 must satisfy the program type's return value contract",
        ))

    # Branches (JMP/JMP32 excluding CALL/EXIT) have no memory safety conditions.
    # LD (0x00) also has minimal safety concerns (mainly BTF/map metadata).

    return conditions


# ---------------------------------------------------------------------------
# Safety condition evaluation against register state
# ---------------------------------------------------------------------------

def evaluate_condition(
    condition: SafetyCondition,
    register_state: dict[str, Any],
) -> str:
    """Evaluate a safety condition against a register state snapshot.

    Args:
        condition: A SafetyCondition derived from the opcode.
        register_state: dict of register name -> RegisterState.

    Returns:
        'satisfied', 'violated', or 'unknown'
    """
    reg = register_state.get(condition.critical_register)
    if reg is None:
        return "unknown"

    reg_type = getattr(reg, "type", "") or ""

    match condition.domain:
        case SafetyDomain.POINTER_TYPE:
            if is_pointer_type_name(reg_type):
                return "satisfied"
            if _is_scalar_like(reg_type):
                return "violated"   # scalar where pointer is required
            return "unknown"

        case SafetyDomain.NULL_SAFETY:
            if is_nullable_pointer_type(reg_type):
                return "violated"   # ptr_or_null — null check not done
            if is_pointer_type_name(reg_type):
                return "satisfied"  # concrete pointer, non-null
            return "unknown"

        case SafetyDomain.MEMORY_BOUNDS:
            if not is_pointer_type_name(reg_type):
                return "unknown"    # can't check bounds on non-pointer
            off = getattr(reg, "off", None) or 0
            rng = getattr(reg, "range", None)
            if rng is None:
                return "unknown"
            if rng == 0:
                return "violated"   # no range proven accessible
            access_size = condition.access_size or 1
            if off + access_size > rng:
                return "violated"
            return "satisfied"

        case SafetyDomain.SCALAR_BOUND:
            return _evaluate_scalar_bound_reg(reg)

        case SafetyDomain.ARITHMETIC_LEGALITY:
            if not is_pointer_type_name(reg_type):
                return "satisfied"  # scalar-scalar arithmetic is always legal
            # ctx and sock pointers prohibit arithmetic
            prohibited = {"ctx", "sock", "sock_or_null", "ptr_sock"}
            if reg_type.lower() in prohibited:
                return "violated"
            return "satisfied"      # pkt/map_value/fp allow arithmetic

        case SafetyDomain.WRITE_PERMISSION:
            # Cannot determine write permission from register state alone;
            # the verifier tracks this via rdonly_mem type annotation.
            if "rdonly" in reg_type.lower():
                return "violated"
            return "unknown"

        case SafetyDomain.ARG_CONTRACT:
            return _evaluate_helper_arg_contract(condition, reg)

        case SafetyDomain.REFERENCE_BALANCE:
            # This requires cross-instruction knowledge.
            return "unknown"

        case _:
            return "unknown"


def compute_condition_gap(
    condition: SafetyCondition,
    register_state: dict[str, Any],
) -> int | None:
    """Return a numeric distance to satisfying a SafetyCondition."""
    reg = register_state.get(condition.critical_register)
    if reg is None:
        return None

    reg_type = getattr(reg, "type", "") or ""

    match condition.domain:
        case SafetyDomain.POINTER_TYPE:
            if is_pointer_type_name(reg_type):
                return 0
            return 1 if reg_type else None

        case SafetyDomain.NULL_SAFETY:
            if is_nullable_pointer_type(reg_type):
                return 1
            if is_pointer_type_name(reg_type):
                return 0
            return 1 if reg_type else None

        case SafetyDomain.MEMORY_BOUNDS:
            if not is_pointer_type_name(reg_type):
                return 1 if reg_type else None
            rng = getattr(reg, "range", None)
            if rng is None:
                return _UNKNOWN_NUMERIC_GAP
            off = getattr(reg, "off", None) or 0
            access_size = condition.access_size or 1
            return max(0, off + access_size - rng)

        case SafetyDomain.SCALAR_BOUND:
            if not _is_scalar_like(reg_type):
                return None
            umax = getattr(reg, "umax", None)
            smax = getattr(reg, "smax", None)
            if umax is None and smax is None:
                return _UNKNOWN_NUMERIC_GAP
            if umax is not None:
                return max(0, umax - ((1 << 32) - 1))
            return 0

        case SafetyDomain.ARITHMETIC_LEGALITY:
            if not is_pointer_type_name(reg_type):
                return 0
            prohibited = {"ctx", "sock", "sock_or_null", "ptr_sock"}
            return 1 if reg_type.lower() in prohibited else 0

        case SafetyDomain.WRITE_PERMISSION:
            if not reg_type:
                return None
            return 1 if "rdonly" in reg_type.lower() else 0

        case SafetyDomain.ARG_CONTRACT:
            result = _evaluate_helper_arg_contract(condition, reg)
            if result == "satisfied":
                return 0
            if result == "violated":
                return 1
            return _UNKNOWN_NUMERIC_GAP

        case SafetyDomain.REFERENCE_BALANCE:
            return None

        case _:
            return None


# ---------------------------------------------------------------------------
# Schema-driven cross-analysis helpers
# ---------------------------------------------------------------------------

_POINTER_KIND_MAP = {
    "ctx": "ctx",
    "dynptr": "dynptr",
    "fp": "fp",
    "map_ptr": "map_ptr",
    "map_value": "map_value",
    "map_value_or_null": "map_value",
    "pkt": "pkt",
    "pkt_end": "pkt_end",
    "pkt_meta": "pkt_meta",
    "ptr": "ptr",
    "ptr_or_null": "ptr",
    "ptr_sock": "sock",
    "ringbuf_mem": "ringbuf_mem",
    "sock": "sock",
    "sock_or_null": "sock",
    "trusted_ptr": "trusted_ptr",
}


def normalize_pointer_kind(type_str: str) -> str | None:
    """Normalize a parsed RegisterState.type token to a carrier kind."""
    normalized = (type_str or "").strip().lower()
    if not normalized:
        return None
    return _POINTER_KIND_MAP.get(normalized)


def infer_safety_schemas(error_insn: Any) -> list[SafetySchema]:
    """Infer register-parametric safety schemas from the reject opcode."""
    bytecode = getattr(error_insn, "bytecode", "") or ""
    raw_opcode = (
        getattr(error_insn, "opcode_hex", None)
        or getattr(error_insn, "_opcode_hex", None)
    )
    if not raw_opcode:
        return []

    info = decode_opcode(raw_opcode, bytecode)
    state = getattr(error_insn, "pre_state", {}) or {}

    def _pointer_kind_for(reg_name: str | None) -> str | None:
        if reg_name is None:
            return None
        reg = state.get(reg_name)
        if reg is None:
            return None
        return normalize_pointer_kind(getattr(reg, "type", "") or "")

    schemas: list[SafetySchema] = []

    if info.opclass == OpcodeClass.LDX:
        pointer_kind = _pointer_kind_for(info.src_reg)
        schemas.extend([
            SafetySchema(
                domain=SafetyDomain.POINTER_TYPE,
                role=OperandRole.BASE_PTR,
                pointer_kind=pointer_kind,
            ),
            SafetySchema(
                domain=SafetyDomain.NULL_SAFETY,
                role=OperandRole.BASE_PTR,
                pointer_kind=pointer_kind,
            ),
            SafetySchema(
                domain=SafetyDomain.MEMORY_BOUNDS,
                role=OperandRole.BASE_PTR,
                access_size=info.access_size,
                pointer_kind=pointer_kind,
            ),
        ])
        return schemas

    if info.opclass in (OpcodeClass.ST, OpcodeClass.STX):
        pointer_kind = _pointer_kind_for(info.dst_reg)
        schemas.extend([
            SafetySchema(
                domain=SafetyDomain.POINTER_TYPE,
                role=OperandRole.BASE_PTR,
                pointer_kind=pointer_kind,
            ),
            SafetySchema(
                domain=SafetyDomain.NULL_SAFETY,
                role=OperandRole.BASE_PTR,
                pointer_kind=pointer_kind,
            ),
            SafetySchema(
                domain=SafetyDomain.MEMORY_BOUNDS,
                role=OperandRole.BASE_PTR,
                access_size=info.access_size,
                pointer_kind=pointer_kind,
            ),
            SafetySchema(
                domain=SafetyDomain.WRITE_PERMISSION,
                role=OperandRole.BASE_PTR,
                pointer_kind=pointer_kind,
            ),
        ])
        return schemas

    if info.is_alu:
        schemas.append(SafetySchema(
            domain=SafetyDomain.ARITHMETIC_LEGALITY,
            role=OperandRole.BASE_PTR,
            pointer_kind=_pointer_kind_for(info.dst_reg),
        ))
        if info.src_reg is not None:
            schemas.append(SafetySchema(
                domain=SafetyDomain.SCALAR_BOUND,
                role=OperandRole.OFFSET_SCALAR,
            ))
        return schemas

    if info.is_call:
        helper_conditions = (
            get_helper_safety_conditions(info.helper_id)
            if info.helper_id is not None
            else []
        )
        if helper_conditions:
            for condition in helper_conditions:
                arg_index = _helper_arg_index(condition.critical_register)
                schemas.append(SafetySchema(
                    domain=condition.domain,
                    role=OperandRole.HELPER_ARG,
                    pointer_kind=_pointer_kind_for(condition.critical_register),
                    expected_types=condition.expected_types,
                    allow_null=condition.allow_null,
                    requires_range=condition.requires_range,
                    requires_writable=condition.requires_writable,
                    helper_id=condition.helper_id,
                    helper_name=condition.helper_name,
                    helper_arg_index=arg_index,
                    constraint=condition.constraint,
                ))
            return schemas

        for register in ("R1", "R2", "R3", "R4", "R5"):
            schemas.append(SafetySchema(
                domain=SafetyDomain.ARG_CONTRACT,
                role=OperandRole.HELPER_ARG,
                pointer_kind=_pointer_kind_for(register),
                helper_id=info.helper_id,
                helper_name=info.call_target,
                helper_arg_index=_helper_arg_index(register),
            ))
        return schemas

    if info.is_exit:
        return [
            SafetySchema(
                domain=SafetyDomain.REFERENCE_BALANCE,
                role=OperandRole.REF_OBJECT,
            ),
            SafetySchema(
                domain=SafetyDomain.SCALAR_BOUND,
                role=OperandRole.RETURN_VALUE,
            ),
        ]

    return []


def instantiate_primary_carrier(
    schema: SafetySchema,
    error_insn: Any,
) -> CarrierSpec | None:
    """Instantiate the reject-site carrier selected by opcode operand roles."""
    bytecode = getattr(error_insn, "bytecode", "") or ""
    raw_opcode = (
        getattr(error_insn, "opcode_hex", None)
        or getattr(error_insn, "_opcode_hex", None)
    )
    if not raw_opcode:
        return None

    info = decode_opcode(raw_opcode, bytecode)
    register: str | None = None

    if schema.role == OperandRole.BASE_PTR:
        if info.opclass == OpcodeClass.LDX:
            register = info.src_reg
        elif info.opclass in (OpcodeClass.ST, OpcodeClass.STX):
            register = info.dst_reg
        elif info.is_alu:
            register = info.dst_reg
    elif schema.role == OperandRole.OFFSET_SCALAR:
        register = info.src_reg
    elif schema.role == OperandRole.HELPER_ARG and schema.helper_arg_index is not None:
        register = f"R{schema.helper_arg_index}"
    elif schema.role in {OperandRole.RETURN_VALUE, OperandRole.REF_OBJECT}:
        register = "R0"

    if register is None:
        return None

    state = getattr(error_insn, "pre_state", {}) or {}
    reg = state.get(register)
    reject_type = getattr(reg, "type", None) if reg is not None else None
    pointer_kind = (
        normalize_pointer_kind(reject_type or "")
        if reject_type is not None
        else schema.pointer_kind
    )

    return CarrierSpec(
        register=register,
        role=schema.role,
        pointer_kind=pointer_kind,
        provenance_id=getattr(reg, "id", None) if reg is not None else None,
        reject_type=reject_type,
        is_primary=True,
    )


def instantiate_schema(schema: SafetySchema, carrier: CarrierSpec) -> SafetyCondition:
    """Bind a register-parametric schema to a concrete carrier register."""
    return SafetyCondition(
        domain=schema.domain,
        critical_register=carrier.register,
        required_property=_schema_required_property(schema),
        access_size=schema.access_size,
        expected_types=schema.expected_types,
        allow_null=schema.allow_null,
        requires_range=schema.requires_range,
        requires_writable=schema.requires_writable,
        helper_id=schema.helper_id,
        helper_name=schema.helper_name,
        constraint=schema.constraint,
    )


def discover_compatible_carriers(
    schema: SafetySchema,
    primary: CarrierSpec,
    reject_state: dict[str, Any],
) -> list[CarrierSpec]:
    """Find reject-site carriers in the same alias class as the primary."""
    if not _schema_supports_carrier_expansion(schema):
        return [primary]

    if primary.pointer_kind is None or primary.provenance_id is None:
        return [primary]

    carriers_by_reg: dict[str, CarrierSpec] = {
        primary.register: primary,
    }

    for register, reg_state in reject_state.items():
        reg_type = getattr(reg_state, "type", "") or ""
        if normalize_pointer_kind(reg_type) != primary.pointer_kind:
            continue
        if getattr(reg_state, "id", None) != primary.provenance_id:
            continue
        carriers_by_reg[register] = CarrierSpec(
            register=register,
            role=primary.role,
            pointer_kind=primary.pointer_kind,
            provenance_id=primary.provenance_id,
            reject_type=reg_type,
            is_primary=(register == primary.register),
        )

    ordered_registers = sorted(carriers_by_reg, key=_register_sort_key)
    if primary.register in ordered_registers:
        ordered_registers.remove(primary.register)
        ordered_registers.insert(0, primary.register)
    return [carriers_by_reg[register] for register in ordered_registers]


def _helper_arg_index(register: str | None) -> int | None:
    if not register or not register.startswith("R"):
        return None
    suffix = register[1:]
    return int(suffix) if suffix.isdigit() else None


def _register_sort_key(register: str) -> tuple[int, str]:
    if register.startswith("R"):
        suffix = register[1:]
        if suffix.isdigit():
            return int(suffix), register
    return 1 << 30, register


def _schema_supports_carrier_expansion(schema: SafetySchema) -> bool:
    if schema.domain in {SafetyDomain.SCALAR_BOUND, SafetyDomain.REFERENCE_BALANCE}:
        return False
    if schema.domain != SafetyDomain.ARG_CONTRACT:
        return True
    return any(expected != "scalar" for expected in schema.expected_types)


def _schema_required_property(schema: SafetySchema) -> str:
    match schema.domain:
        case SafetyDomain.MEMORY_BOUNDS:
            size = schema.access_size if schema.access_size is not None else "?"
            return f"off + {size} <= range"
        case SafetyDomain.POINTER_TYPE:
            if schema.pointer_kind is not None:
                return f"must be a valid {schema.pointer_kind} pointer"
            return "must be a valid pointer type"
        case SafetyDomain.NULL_SAFETY:
            return "must not be nullable at use site"
        case SafetyDomain.SCALAR_BOUND:
            return "scalar must have bounded unsigned range"
        case SafetyDomain.ARG_CONTRACT:
            helper = schema.helper_name or f"helper#{schema.helper_id}" if schema.helper_id is not None else "helper"
            arg = f"arg#{schema.helper_arg_index}" if schema.helper_arg_index is not None else "arg"
            return f"{helper} {arg} must satisfy the helper contract"
        case SafetyDomain.WRITE_PERMISSION:
            return "pointee must be writable"
        case SafetyDomain.ARITHMETIC_LEGALITY:
            return "pointer arithmetic must be legal for this pointer kind"
        case SafetyDomain.REFERENCE_BALANCE:
            return "all acquired references must be released before exit"
        case _:
            return schema.domain.value


# ---------------------------------------------------------------------------
# High-level: infer conditions from the error instruction's opcode
# ---------------------------------------------------------------------------

def infer_conditions_from_error_insn(
    error_insn: Any,
    error_register: str | None = None,
) -> list[SafetyCondition]:
    """Derive safety conditions from the error instruction's opcode byte.

    This is the primary entry point for opcode-driven analysis.
    No error message parsing. No keyword heuristics.

    Args:
        error_insn: A TracedInstruction with .bytecode (str) and .opcode attribute.
                    The opcode may be a hex string (from InstructionLine) or None.

    Returns:
        List of SafetyCondition objects (may be empty if opcode not available).
    """
    bytecode = getattr(error_insn, "bytecode", "") or ""
    raw_opcode = (
        getattr(error_insn, "opcode_hex", None)
        or getattr(error_insn, "_opcode_hex", None)
    )

    if not raw_opcode:
        return []
    info = decode_opcode(raw_opcode, bytecode)

    conditions = derive_safety_conditions(info, error_register=error_register)

    # Refine using register state at the error point:
    # For ALU conditions, only keep pointer-arithmetic conditions if dst IS a pointer,
    # and scalar-bound conditions only if the register IS a scalar.
    state = getattr(error_insn, "pre_state", {}) or {}
    refined: list[SafetyCondition] = []
    for cond in conditions:
        reg = state.get(cond.critical_register)
        if reg is None:
            refined.append(cond)
            continue
        reg_type = getattr(reg, "type", "") or ""
        if cond.domain == SafetyDomain.ARITHMETIC_LEGALITY:
            # Only keep if dst IS a pointer (scalar ALU has no safety conditions)
            if is_pointer_type_name(reg_type):
                refined.append(cond)
        elif cond.domain == SafetyDomain.SCALAR_BOUND:
            # Only keep if register IS a scalar
            if _is_scalar_like(reg_type):
                refined.append(cond)
        else:
            refined.append(cond)

    return refined


def _infer_opcode_class_from_bytecode(bytecode: str) -> OpcodeInfo | None:
    """Infer OpcodeInfo from bytecode text when the raw opcode byte is unavailable.

    This is used when TracedInstruction does not carry the raw opcode.
    We heuristically identify the instruction class from the text.
    """
    if not bytecode:
        return None

    text = bytecode.strip().lower()

    # Memory load: "rN = *(uN *)(rM + off)"
    if re.match(r"[rw]\d+\s*=\s*\*\(", text):
        src_reg, dst_reg = _extract_regs_from_bytecode(bytecode)
        # Access size from type annotation
        size = _extract_access_size_from_bytecode(text)
        return OpcodeInfo(
            raw=0x01,  # LDX
            opclass=OpcodeClass.LDX,
            is_memory_access=True,
            is_call=False,
            is_exit=False,
            is_alu=False,
            is_branch=False,
            access_size=size,
            src_reg=src_reg,
            dst_reg=dst_reg,
        )

    # Memory store register: "*(uN *)(rM + off) = rK"
    if re.match(r"\*\(", text):
        src_reg, dst_reg = _extract_regs_from_bytecode(bytecode)
        size = _extract_access_size_from_bytecode(text)
        # STX if src_reg present, ST if immediate
        is_stx = src_reg is not None
        return OpcodeInfo(
            raw=0x03 if is_stx else 0x02,
            opclass=OpcodeClass.STX if is_stx else OpcodeClass.ST,
            is_memory_access=True,
            is_call=False,
            is_exit=False,
            is_alu=False,
            is_branch=False,
            access_size=size,
            src_reg=src_reg,
            dst_reg=dst_reg,
        )

    # CALL
    if text.startswith("call "):
        call_target, helper_id = _extract_call_target(bytecode)
        return OpcodeInfo(
            raw=BPF_CALL,
            opclass=OpcodeClass.JMP,
            is_memory_access=False,
            is_call=True,
            is_exit=False,
            is_alu=False,
            is_branch=False,
            access_size=None,
            src_reg=None,
            dst_reg=None,
            call_target=call_target,
            helper_id=helper_id,
        )

    # EXIT
    if text.startswith("exit"):
        return OpcodeInfo(
            raw=BPF_EXIT,
            opclass=OpcodeClass.JMP,
            is_memory_access=False,
            is_call=False,
            is_exit=True,
            is_alu=False,
            is_branch=False,
            access_size=None,
            src_reg=None,
            dst_reg=None,
        )

    # Branches: "if rN <op> rM/imm, goto ..."
    if re.match(r"if\s|goto\s", text):
        return OpcodeInfo(
            raw=0x05,  # JMP
            opclass=OpcodeClass.JMP,
            is_memory_access=False,
            is_call=False,
            is_exit=False,
            is_alu=False,
            is_branch=True,
            access_size=None,
            src_reg=None,
            dst_reg=None,
        )

    # ALU: "rN op= rM" or "rN op= imm"
    if re.match(r"[rw]\d+\s*(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|=)", text):
        src_reg, dst_reg = _extract_regs_from_bytecode(bytecode)
        return OpcodeInfo(
            raw=0x07,  # ALU64
            opclass=OpcodeClass.ALU64,
            is_memory_access=False,
            is_call=False,
            is_exit=False,
            is_alu=True,
            is_branch=False,
            access_size=None,
            src_reg=src_reg,
            dst_reg=dst_reg,
        )

    # Byte-swap: "be16/be32/be64 rN" or "le16/le32/le64 rN"
    if re.match(r"(?:be|le)\d+\s", text):
        m = re.match(r"(?:be|le)\d+\s+(?P<reg>[rw]\d+)", text)
        dst_reg = _normalize_reg(m.group("reg")) if m else None
        return OpcodeInfo(
            raw=0x04,  # ALU (byte-swap is ALU class)
            opclass=OpcodeClass.ALU,
            is_memory_access=False,
            is_call=False,
            is_exit=False,
            is_alu=True,
            is_branch=False,
            access_size=None,
            src_reg=None,
            dst_reg=dst_reg,
        )

    return None


def _extract_access_size_from_bytecode(text: str) -> int | None:
    """Extract memory access size in bytes from a bytecode text.

    Examples:
      "*(u8 *)(r0 +2)" -> 1
      "*(u16 *)(r0 +2)" -> 2
      "*(u32 *)(r0 +4)" -> 4
      "*(u64 *)(r10 -8)" -> 8
    """
    m = re.search(r"\*\(u(\d+)\s*\*\)", text)
    if m:
        bits = int(m.group(1))
        return bits // 8
    return None


def _is_scalar_like(reg_type: str) -> bool:
    """Return True if the type represents a scalar (non-pointer) value."""
    lowered = reg_type.lower()
    return (
        lowered.startswith("inv")
        or lowered.startswith("scalar")
        or lowered == "unknown"
    )


def _extract_call_target(bytecode: str) -> tuple[str | None, int | None]:
    """Extract the textual CALL target and helper ID from bytecode text."""
    if not bytecode:
        return None, None

    match = _CALL_TARGET_RE.match(bytecode.strip())
    if match is None:
        return None, None

    if match.group("pc") is not None:
        return match.group("pc"), None

    helper_name = match.group("name")
    helper_id_text = match.group("helper_id") or match.group("imm")
    helper_id = int(helper_id_text) if helper_id_text is not None else None

    normalized_name: str | None
    if helper_name is None:
        normalized_name = None
    elif helper_name.startswith("bpf_"):
        normalized_name = helper_name
    else:
        normalized_name = f"bpf_{helper_name}"

    if helper_id is None and normalized_name is not None:
        helper_id = get_helper_id_by_name(normalized_name)

    return normalized_name, helper_id


def _evaluate_scalar_bound_reg(reg: Any) -> str:
    reg_type = getattr(reg, "type", "") or ""
    if not _is_scalar_like(reg_type):
        return "unknown"

    umax = getattr(reg, "umax", None)
    smax = getattr(reg, "smax", None)
    if umax is None and smax is None:
        return "violated"
    if umax is not None and umax < (1 << 32):
        return "satisfied"
    if umax is not None and umax >= (1 << 32):
        return "violated"
    return "unknown"


def _evaluate_helper_arg_contract(condition: SafetyCondition, reg: Any) -> str:
    reg_type = getattr(reg, "type", "") or ""
    expected_types = condition.expected_types
    if not expected_types:
        return "unknown"

    if not any(_matches_helper_expected_type(reg_type, expected) for expected in expected_types):
        if is_pointer_type_name(reg_type) or _is_scalar_like(reg_type):
            return "violated"
        return "unknown"

    if is_nullable_pointer_type(reg_type) and not condition.allow_null:
        return "violated"

    if condition.requires_range and reg_type.lower() != "fp":
        rng = getattr(reg, "range", None)
        if rng == 0:
            return "violated"
        if rng is None:
            return "unknown"

    if condition.requires_writable and "rdonly" in reg_type.lower():
        return "violated"

    if expected_types == ("scalar",):
        return "satisfied" if _is_scalar_like(reg_type) else "violated"

    return "satisfied"


def _matches_helper_expected_type(reg_type: str, expected_type: str) -> bool:
    lowered = reg_type.lower()

    if expected_type == "scalar":
        return _is_scalar_like(lowered)
    if expected_type == "ptr":
        return is_pointer_type_name(lowered)
    if expected_type == "map_ptr":
        return lowered == "map_ptr"
    if expected_type == "ctx":
        return lowered == "ctx"
    if expected_type == "fp":
        return lowered == "fp"
    if expected_type == "sock":
        return lowered.startswith("sock") or lowered == "ptr_sock"
    if expected_type == "dynptr":
        return lowered.startswith("dynptr")

    return False


# ---------------------------------------------------------------------------
# Predicate adapter: wrap SafetyCondition into the Predicate interface
# ---------------------------------------------------------------------------

class OpcodeConditionPredicate:
    """Adapter that wraps a SafetyCondition into the Predicate protocol.

    This allows the opcode-driven analysis to be used with TraceMonitor
    and TransitionAnalyzer without changing those components.

    The Predicate protocol requires:
    - evaluate(state, insn=None) -> 'satisfied'|'violated'|'unknown'
    - describe_violation(state, insn=None) -> str
    - target_regs: list[str]  (used by pipeline to determine proof_registers)
    """

    def __init__(self, condition: SafetyCondition) -> None:
        self.condition = condition
        self.target_regs: list[str] = [condition.critical_register]

    def evaluate(self, state: dict, insn: Any = None) -> str:
        return evaluate_condition(self.condition, state)

    def compute_gap(self, state: dict, insn: Any = None) -> int | None:
        return compute_condition_gap(self.condition, state)

    def describe_violation(self, state: dict, insn: Any = None) -> str:
        reg = state.get(self.condition.critical_register)
        if reg is None:
            return (
                f"OpcodeCondition[{self.condition.domain.value}]: "
                f"{self.condition.critical_register} not in state; "
                f"required: {self.condition.required_property}"
            )
        reg_type = getattr(reg, "type", "unknown")
        umax = getattr(reg, "umax", None)
        rng = getattr(reg, "range", None)
        off = getattr(reg, "off", None)
        details = f"type={reg_type}"
        if umax is not None:
            details += f", umax={umax}"
        if rng is not None:
            details += f", range={rng}"
        if off is not None:
            details += f", off={off}"
        return (
            f"OpcodeCondition[{self.condition.domain.value}] violated on "
            f"{self.condition.critical_register} ({details}): "
            f"required={self.condition.required_property}"
        )

    def __repr__(self) -> str:
        return (
            f"OpcodeConditionPredicate({self.condition.domain.value}, "
            f"reg={self.condition.critical_register})"
        )


# ---------------------------------------------------------------------------
# Find the violated condition at the error instruction
# ---------------------------------------------------------------------------

def find_violated_condition(
    error_insn: Any,
    conditions: list[SafetyCondition],
) -> SafetyCondition | None:
    """Identify which safety condition is violated at the error instruction.

    Evaluates each condition against the pre-state of the error instruction.
    Returns the first violated condition, or the first condition if none is
    explicitly violated (best-effort fallback).

    Args:
        error_insn: TracedInstruction at the error site.
        conditions: List of SafetyConditions from infer_conditions_from_error_insn().

    Returns:
        The violated SafetyCondition, or None if conditions is empty.
    """
    if not conditions:
        return None

    state = getattr(error_insn, "pre_state", {}) or {}

    for cond in conditions:
        result = evaluate_condition(cond, state)
        if result == "violated":
            return cond

    # No explicitly violated condition found — return the first (primary) condition
    # as a best-effort fallback.
    return conditions[0]
