#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
import re

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def ipv4_frame(protocol: int) -> bytes:
    ip = bytearray(b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x00\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02")
    ip[9] = protocol
    return bytes.fromhex("00112233445566778899aabb0800") + bytes(ip) + (b"\x00" * 44)


def short_packet() -> bytes:
    return bytes.fromhex("00112233")


def two_dynptr_slices(load_output: str) -> bool:
    return len(re.findall(r"\bbpf_dynptr_slice\b", load_output)) >= 2


def direct_packet_precheck_before_dynptr(load_output: str) -> bool:
    in_trace = False
    saw_data_end = False
    saw_data = False
    saw_bounds_check = False
    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_trace = True
        if not in_trace:
            continue
        if "call bpf_dynptr_from_xdp#" in line:
            return saw_data_end and saw_data and saw_bounds_check
        if "*(u32 *)(r1 +4)" in line:
            saw_data_end = True
        if "*(u32 *)(r1 +0)" in line:
            saw_data = True
        if re.search(r"\bif r\d+ > r\d+ goto", line):
            saw_bounds_check = True
    return False


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'rdonly_mem_or_null'",
            ],
            functional_tests=[
                ("ipv4_udp_drops", lambda: ipv4_frame(17), 1),
                ("ipv4_tcp_passes", lambda: ipv4_frame(6), 2),
                ("arp_passes", lambda: frame(0x0806), 2),
                ("short_packet_passes", short_packet, 2),
            ],
            required_success_substrings=[
                "bpf_dynptr_from_xdp",
                "bpf_dynptr_slice",
            ],
            required_success_predicates=[
                ("two dynptr slices are preserved", two_dynptr_slices),
                ("direct packet precheck before dynptr", direct_packet_precheck_before_dynptr),
            ],
        )
    )
