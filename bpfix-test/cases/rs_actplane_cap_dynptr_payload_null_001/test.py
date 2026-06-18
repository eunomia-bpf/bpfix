#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


CAP_REQ_RELOAD_UPDATE = 1001
CAP_REQ_RELOAD_RULE = 1002


def packet(payload: bytes, *, declared_len: int | None = None, truncate_to: int | None = None) -> bytes:
    if declared_len is None:
        declared_len = len(payload)
    body = payload if truncate_to is None else payload[:truncate_to]
    data = bytes([declared_len]) + body
    if len(data) < 14:
        data += b"\x00" * (14 - len(data))
    return data


def reload_update(index: int, value: int) -> bytes:
    return struct.pack("<iII", CAP_REQ_RELOAD_UPDATE, index, value)


def reload_rule(index: int, domain: int, action: int) -> bytes:
    return struct.pack("<iIII", CAP_REQ_RELOAD_RULE, index, domain, action)


def unknown_request() -> bytes:
    return struct.pack("<iII", 7777, 0, 0)


def dynptr_payload_fields_read_from_proven_mem(load_output: str) -> bool:
    payload_regs: dict[str, tuple[int, int]] = {}
    update_offsets: set[int] = set()
    rule_offsets: set[int] = set()
    saw_from_mem = "call bpf_dynptr_from_mem#197" in load_output
    saw_tag_data = False
    saw_struct_data = False

    for line in load_output.splitlines():
        if "call bpf_dynptr_data#203" in line:
            payload_regs.clear()

        for register, state in re.findall(r"\bR(\d+)(?:_w)?=([^\s;]+)", line):
            size_match = re.search(r"^mem\(.*sz=(\d+)", state)
            if size_match is not None:
                size = int(size_match.group(1))
                off_match = re.search(r"off=(\d+)", state)
                base_offset = int(off_match.group(1)) if off_match is not None else 0
                if size == 4:
                    saw_tag_data = True
                    payload_regs.pop(register, None)
                elif size in {12, 16}:
                    saw_struct_data = True
                    payload_regs[register] = (size, base_offset)
                else:
                    payload_regs.pop(register, None)
            elif not state.startswith("mem("):
                payload_regs.pop(register, None)

        copy = re.search(r"\br(\d+)\s*=\s*r(\d+)\b", line)
        if copy is not None:
            dst, src = copy.group(1), copy.group(2)
            if src in payload_regs:
                payload_regs[dst] = payload_regs[src]
            else:
                payload_regs.pop(dst, None)

        ptr_add = re.search(r"\br(\d+)\s*\+=\s*(\d+)\b", line)
        if ptr_add is not None and ptr_add.group(1) in payload_regs:
            register = ptr_add.group(1)
            size, base_offset = payload_regs[register]
            payload_regs[register] = (size, base_offset + int(ptr_add.group(2)))

        load = re.search(r"=\s*\*\(u32 \*\)\(r(\d+)\s*\+(\d+)\)", line)
        if load is None:
            continue
        register, offset = load.group(1), int(load.group(2))
        payload_state = payload_regs.get(register)
        if payload_state is None:
            continue
        size, base_offset = payload_state
        offset += base_offset
        if size == 12:
            update_offsets.add(offset)
        elif size == 16:
            rule_offsets.add(offset)

    return (
        saw_from_mem
        and saw_tag_data
        and saw_struct_data
        and {4, 8}.issubset(update_offsets)
        and {4, 8, 12}.issubset(rule_offsets)
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'mem_or_null'",
                "call bpf_dynptr_data#203",
            ],
            functional_tests=[
                ("reload_update_value_drops", lambda: packet(reload_update(3, 0x55)), 1),
                ("reload_update_other_value_passes", lambda: packet(reload_update(3, 0x44)), 2),
                ("reload_update_bad_index_passes", lambda: packet(reload_update(9, 0x55)), 2),
                ("reload_rule_match_drops", lambda: packet(reload_rule(2, 7, 9)), 1),
                ("reload_rule_bad_action_passes", lambda: packet(reload_rule(2, 7, 8)), 2),
                ("reload_rule_bad_index_passes", lambda: packet(reload_rule(5, 7, 9)), 2),
                ("tag_only_passes", lambda: packet(reload_update(3, 0x55), declared_len=4, truncate_to=4), 2),
                ("short_packet_passes", lambda: packet(reload_update(3, 0x55), declared_len=32, truncate_to=5), 2),
                ("unknown_tag_passes", lambda: packet(unknown_request()), 2),
            ],
            required_success_substrings=[
                "call bpf_dynptr_from_mem#197",
                "call bpf_dynptr_data#203",
            ],
            required_success_predicates=[
                (
                    "reload update and rule payload fields are read from proven dynptr memory",
                    dynptr_payload_fields_read_from_proven_mem,
                ),
            ],
        )
    )
