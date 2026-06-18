#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


INSN_RE = re.compile(r"^\s*(\d+): \([0-9a-f]{2}\) (.*)$", re.MULTILINE)


def cfg_value(blocked_port: int, snap_len: int, enable_ringbuf: int) -> bytes:
    return (
        blocked_port.to_bytes(2, "little")
        + b"\0\0"
        + snap_len.to_bytes(4, "little")
        + bytes([enable_ringbuf])
        + b"\0\0\0"
    )


def tcp_packet(dst_port: int, payload: bytes = b"abcdefgh") -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb") + (0x0800).to_bytes(2, "big")
    total_len = 20 + 20 + len(payload)
    ip = bytes(
        [
            0x45,
            0,
            (total_len >> 8) & 0xff,
            total_len & 0xff,
            0,
            0,
            0,
            0,
            64,
            6,
            0,
            0,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
        ]
    )
    tcp = (
        (1234).to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
        + b"\0\0\0\0"
        + b"\0\0\0\0"
        + bytes([0x50, 0x18])
        + b"\0\0"
        + b"\0\0"
        + b"\0\0"
    )
    return eth + ip + tcp + payload


def arp_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + (0x0806).to_bytes(2, "big") + (b"\0" * 46)


def dynptr_protocol_is_preserved(load_output: str) -> bool:
    reserve = load_output.find("call bpf_ringbuf_reserve_dynptr#198")
    first_write = load_output.find("call bpf_dynptr_write#202", reserve)
    second_write = load_output.find("call bpf_dynptr_write#202", first_write + 1)
    discard = load_output.find("call bpf_ringbuf_discard_dynptr#200")
    submit = load_output.find("call bpf_ringbuf_submit_dynptr#199")
    return (
        reserve != -1
        and first_write != -1
        and second_write != -1
        and discard != -1
        and submit != -1
        and reserve < first_write < second_write < submit
    )


def parse_instructions(load_output: str) -> dict[int, str]:
    insns: dict[int, str] = {}
    for match in INSN_RE.finditer(load_output):
        pc = int(match.group(1))
        insns.setdefault(pc, match.group(2).strip())
    return insns


def next_pc(insns: dict[int, str], pc: int) -> int | None:
    for candidate in sorted(insns):
        if candidate > pc:
            return candidate
    return None


def is_conditional_branch(op: str) -> bool:
    return op.startswith("if ") and "goto pc" in op


def branch_target(pc: int, op: str) -> int | None:
    match = re.search(r"goto pc([+-]\d+)", op)
    return pc + 1 + int(match.group(1)) if match else None


def successors(insns: dict[int, str], pc: int) -> list[int]:
    op = insns.get(pc)
    if op is None or op == "exit":
        return []
    target = branch_target(pc, op)
    fallthrough = next_pc(insns, pc)
    if is_conditional_branch(op):
        return [succ for succ in [fallthrough, target] if succ is not None]
    if op.startswith("goto pc"):
        return [target] if target is not None else []
    return [fallthrough] if fallthrough is not None else []


def call_pcs(insns: dict[int, str], helper: str) -> list[int]:
    return [pc for pc, op in sorted(insns.items()) if helper in op]


def branch_test_register(op: str) -> str | None:
    match = re.search(r"if (r\d+) (?:==|!=) 0x?0\b", op)
    return match.group(1) if match else None


def next_return_branch_after(insns: dict[int, str], pc: int, max_steps: int = 8) -> tuple[int, str] | None:
    aliases = {"r0"}
    current = next_pc(insns, pc)
    for _ in range(max_steps):
        if current is None:
            return None
        op = insns[current]
        if is_conditional_branch(op):
            reg = branch_test_register(op)
            return (current, reg) if reg in aliases else None
        if op == "exit" or "call " in op:
            return None
        assign = re.match(r"(r\d+) = (r\d+)\b", op)
        if assign:
            dest, src = assign.group(1), assign.group(2)
            if src in aliases:
                aliases.add(dest)
            elif dest in aliases:
                aliases.remove(dest)
        current = next_pc(insns, current)
    return None


def return_branch_paths(insns: dict[int, str], branch_pc: int, reg: str) -> tuple[int, int] | None:
    op = insns.get(branch_pc, "")
    target = branch_target(branch_pc, op)
    fallthrough = next_pc(insns, branch_pc)
    if target is None or fallthrough is None:
        return None
    if re.search(rf"if {reg} != 0x?0\b", op):
        return target, fallthrough
    if re.search(rf"if {reg} == 0x?0\b", op):
        return fallthrough, target
    return None


def reaches_target_before_forbidden(
    insns: dict[int, str],
    start: int,
    targets: set[int],
    forbidden: set[int],
) -> bool:
    stack = [start]
    seen: set[int] = set()
    while stack:
        pc = stack.pop()
        if pc in seen:
            continue
        seen.add(pc)
        if pc in targets:
            return True
        if pc in forbidden or pc not in insns:
            continue
        stack.extend(successors(insns, pc))
    return False


def reserve_error_path_discards(load_output: str) -> bool:
    insns = parse_instructions(load_output)
    reserve_pcs = call_pcs(insns, "call bpf_ringbuf_reserve_dynptr#198")
    write_pcs = set(call_pcs(insns, "call bpf_dynptr_write#202"))
    submit_pcs = set(call_pcs(insns, "call bpf_ringbuf_submit_dynptr#199"))
    exit_pcs = {pc for pc, op in insns.items() if op == "exit"}
    if not reserve_pcs or not write_pcs or not submit_pcs:
        return False
    branch = next_return_branch_after(insns, reserve_pcs[0])
    if branch is None:
        return False
    branch_pc, reg = branch
    paths = return_branch_paths(insns, branch_pc, reg)
    if paths is None:
        return False
    error_start, success_start = paths
    discard_pcs = set(call_pcs(insns, "call bpf_ringbuf_discard_dynptr#200"))
    cleanup_ok = reaches_target_before_forbidden(
        insns,
        error_start,
        discard_pcs,
        write_pcs | submit_pcs | exit_pcs,
    )
    success_ok = reaches_target_before_forbidden(
        insns,
        success_start,
        {min(write_pcs)},
        discard_pcs | exit_pcs,
    )
    return cleanup_ok and success_ok


def write_error_path_discards(load_output: str) -> bool:
    insns = parse_instructions(load_output)
    write_pcs = call_pcs(insns, "call bpf_dynptr_write#202")
    submit_pcs = set(call_pcs(insns, "call bpf_ringbuf_submit_dynptr#199"))
    exit_pcs = {pc for pc, op in insns.items() if op == "exit"}
    if len(write_pcs) < 2 or not submit_pcs:
        return False
    discard_pcs = set(call_pcs(insns, "call bpf_ringbuf_discard_dynptr#200"))
    for write_pc in write_pcs[:2]:
        branch = next_return_branch_after(insns, write_pc)
        if branch is None:
            return False
        branch_pc, reg = branch
        paths = return_branch_paths(insns, branch_pc, reg)
        if paths is None:
            return False
        error_start, success_start = paths
        later_writes = {pc for pc in write_pcs if pc > write_pc}
        normal_targets = later_writes | submit_pcs
        cleanup_ok = reaches_target_before_forbidden(
            insns,
            error_start,
            discard_pcs,
            later_writes | submit_pcs | exit_pcs,
        )
        success_ok = reaches_target_before_forbidden(
            insns,
            success_start,
            normal_targets,
            discard_pcs | exit_pcs,
        )
        if not cleanup_ok or not success_ok:
            return False
    return True


def dynptr_skb_parse_is_preserved(load_output: str) -> bool:
    from_skb = load_output.find("call bpf_dynptr_from_skb")
    slice_calls = len(re.findall("call bpf_dynptr_slice", load_output))
    read = load_output.find("call bpf_dynptr_read#201")
    reserve = load_output.find("call bpf_ringbuf_reserve_dynptr#198")
    return from_skb != -1 and slice_calls >= 3 and read != -1 and from_skb < read < reserve


if __name__ == "__main__":
    key0 = (0).to_bytes(4, "little")
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "Unreleased reference id=",
                "BPF_EXIT instruction in main prog would lead to reference leak",
            ],
            functional_tests=[
                (
                    "blocked_tcp_drops_with_ringbuf",
                    lambda: tcp_packet(443),
                    2,
                    [("cfg_map", key0, cfg_value(443, 8, 1))],
                ),
                (
                    "other_tcp_passes_with_ringbuf",
                    lambda: tcp_packet(80),
                    0,
                    [("cfg_map", key0, cfg_value(443, 8, 1))],
                ),
                (
                    "blocked_tcp_still_drops_without_ringbuf",
                    lambda: tcp_packet(443),
                    2,
                    [("cfg_map", key0, cfg_value(443, 8, 0))],
                ),
                (
                    "non_ipv4_passes",
                    arp_packet,
                    0,
                    [("cfg_map", key0, cfg_value(443, 8, 1))],
                ),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
                "call bpf_ringbuf_reserve_dynptr#198",
                "call bpf_dynptr_write#202",
                "call bpf_ringbuf_discard_dynptr#200",
                "call bpf_ringbuf_submit_dynptr#199",
            ],
            required_success_predicates=[
                ("dynptr skb parse/read workflow preserved", dynptr_skb_parse_is_preserved),
                ("reserve/write/submit dynptr protocol preserved", dynptr_protocol_is_preserved),
                ("reserve-error path discards ringbuf dynptr", reserve_error_path_discards),
                ("write-error paths discard ringbuf dynptr", write_error_path_discards),
            ],
            prog_type=None,
        )
    )
