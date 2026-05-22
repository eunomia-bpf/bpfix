"""Shared extractor helpers for register parsing and verifier type families."""

from __future__ import annotations

import re


REGISTER_RE = re.compile(r"\b([RrWw]\d+)\b")

_EXACT_POINTER_TYPES = {
    "ctx",
    "fp",
    "map_ptr",
    "map_value",
    "map_value_or_null",
    "mem",
    "mem_or_null",
    "pkt",
    "pkt_end",
    "pkt_meta",
    "ptr",
    "ptr_or_null",
    "sock",
    "sock_or_null",
    "ptr_sock",
}
_POINTER_PREFIXES = (
    "map_",
    "mem",
    "pkt",
    "ptr_",
    "trusted_ptr_",
    "rcu_ptr_",
    "sock",
    "dynptr",
    "iter",
)
_MAP_VALUE_PREFIXES = ("map_value", "map_value_or_null")


def normalize_register(register: str) -> str:
    lowered = register.strip().lower()
    if lowered.startswith(("r", "w")) and lowered[1:].isdigit():
        return f"R{lowered[1:]}"
    return register


def extract_registers(text: str | None) -> list[str]:
    if not text:
        return []

    registers: list[str] = []
    for match in REGISTER_RE.finditer(text):
        register = normalize_register(match.group(1))
        if register not in registers:
            registers.append(register)
    return registers


def decode_regs_mask(mask: str | None) -> list[str]:
    if not mask:
        return []

    text = mask.strip()
    textual_registers = extract_registers(text)
    if textual_registers:
        return textual_registers

    lowered = text.lower()
    if lowered in {"0", "0x0"}:
        return []

    try:
        value = int(lowered, 16)
    except ValueError:
        try:
            value = int(lowered, 0)
        except ValueError:
            return []

    registers: list[str] = []
    bit = 0
    while value:
        if value & 1:
            registers.append(f"R{bit}")
        value >>= 1
        bit += 1
    return registers


def register_index(register: str) -> int | None:
    normalized = normalize_register(register)
    if not normalized.startswith("R"):
        return None
    suffix = normalized[1:]
    return int(suffix) if suffix.isdigit() else None


def is_pointer_type_name(state_type: str) -> bool:
    lowered = state_type.lower()
    if lowered in _EXACT_POINTER_TYPES:
        return True
    return any(lowered.startswith(prefix) for prefix in _POINTER_PREFIXES)


def is_packet_pointer_type(state_type: str, *, include_end: bool = False) -> bool:
    lowered = state_type.lower()
    if lowered == "pkt_end":
        return include_end
    if not lowered.startswith("pkt"):
        return False
    if not include_end and "pkt_end" in lowered:
        return False
    return True


def is_map_value_type_name(state_type: str) -> bool:
    lowered = state_type.lower()
    return any(lowered.startswith(prefix) for prefix in _MAP_VALUE_PREFIXES)


def is_nullable_pointer_type(state_type: str) -> bool:
    lowered = state_type.lower()
    return lowered.endswith("_or_null") or "or_null" in lowered
