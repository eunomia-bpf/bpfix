#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def ethernet_packet(ethertype: int, payload: bytes) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ethertype) + payload


def ipv4_packet() -> bytes:
    ip = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,
        20,
        0,
        0,
        64,
        6,
        0,
        0x0A000001,
        0x0A000002,
    )
    return ethernet_packet(0x0800, ip)


def ipv6_packet() -> bytes:
    return ethernet_packet(0x86DD, b"\x60" + (b"\x00" * 39))


def fib_lookup_called_with_struct_len(load_output: str) -> bool:
    r3_is_struct_len = False
    for line in load_output.splitlines():
        if re.search(r"\br3 = 64\b", line) or "R3_w=64" in line:
            r3_is_struct_len = True
        if re.search(r"\br3 = (?!64\b)", line):
            r3_is_struct_len = False
        if "call bpf_fib_lookup#69" in line:
            return r3_is_struct_len
    return False


def fib_stack_object_zeroed_before_helper(load_output: str) -> bool:
    zeroed_offsets: set[int] = set()
    in_trace = False
    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_trace = True
            zeroed_offsets.clear()
        if not in_trace:
            continue
        match = re.search(r"\*\(u64 \*\)\(r10 -(\d+)\) = r\d+", line)
        if match is not None and "R2_w=0" in line:
            zeroed_offsets.add(int(match.group(1)))
        if "call bpf_fib_lookup#69" in line:
            return zeroed_offsets >= {8, 16, 24, 32, 40, 48, 56, 64}
    return False


def fib_success_path_rewrites_l2_and_redirects(load_output: str) -> bool:
    helper = load_output.rfind("call bpf_fib_lookup#69")
    redirect = load_output.find("call bpf_redirect#23", helper)
    if helper == -1 or redirect == -1:
        return False
    region = load_output[helper:redirect]
    return (
        "*(u16 *)(r6 +0)" in region
        and "*(u16 *)(r6 +6)" in region
        and "*(u16 *)(r2 +4)" in region
        and "*(u16 *)(r3 +4)" in region
        and "*(u32 *)(r1 +8)" in region
    )


def fib_param_fields_derive_from_packet_and_ctx(load_output: str) -> bool:
    helper = load_output.rfind("call bpf_fib_lookup#69")
    if helper == -1:
        return False
    before_helper = load_output[:helper]
    return (
        "*(u8 *)(r2 +0) = r4" in before_helper
        and "R4_w=2" in before_helper
        and "*(u32 *)(r2 +16) = r4" in before_helper
        and "*(u32 *)(r2 +32) = r3" in before_helper
        and "*(u32 *)(r2 +8) = r3" in before_helper
        and "*(u32 *)(r3 +12)" in before_helper
        and "*(u32 *)(r3 +16)" in before_helper
        and "*(u32 *)(r1 +12)" in before_helper
    )


def fib_rewrite_is_success_branch(load_output: str) -> bool:
    helper = load_output.rfind("call bpf_fib_lookup#69")
    redirect = load_output.find("call bpf_redirect#23", helper)
    if helper == -1 or redirect == -1:
        return False
    region = load_output[helper:redirect]
    branch = region.find("if r1 != 0x0 goto")
    first_l2_store = region.find("*(u16 *)(r6 +0)")
    return (
        branch != -1
        and first_l2_store != -1
        and "R1_w=0" in region
        and branch < first_l2_store
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid read from stack R2 off=-64 size=68",
            ],
            functional_tests=[
                ("ipv4_lookup_success_redirects", ipv4_packet, 4),
                ("ipv6_packet_passes_without_lookup", ipv6_packet, 2),
            ],
            required_success_substrings=[
                "call bpf_fib_lookup#69",
                "call bpf_redirect#23",
            ],
            required_success_predicates=[
                ("FIB helper receives sizeof(struct bpf_fib_lookup)", fib_lookup_called_with_struct_len),
                ("FIB stack parameter object is fully zeroed before helper", fib_stack_object_zeroed_before_helper),
                ("FIB parameter fields derive from packet and ctx state", fib_param_fields_derive_from_packet_and_ctx),
                ("FIB L2 rewrite is guarded by lookup success", fib_rewrite_is_success_branch),
                ("FIB success path rewrites L2 addresses and redirects", fib_success_path_rewrites_l2_and_redirects),
            ],
        )
    )
