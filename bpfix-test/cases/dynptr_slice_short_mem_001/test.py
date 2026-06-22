#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def ipv4_packet(daddr: int = 0x0A000002, *, truncate_ip_to: int | None = None) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20, 0, 0, 64, 6, 0, 0x0A000001, daddr)
    if truncate_ip_to is not None:
        ip = ip[:truncate_ip_to]
    return eth + ip


def short_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb08")


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
                "invalid access to memory",
            ],
            functional_tests=[
                ("ipv4_target_drops", ipv4_packet, 1),
                ("ipv4_other_dst_passes", lambda: ipv4_packet(0x0A000003), 2),
                ("arp_passes", lambda: frame(0x0806), 2),
                ("truncated_ipv4_passes", lambda: ipv4_packet(truncate_ip_to=19), 2),
                ("short_packet_passes", short_packet, 2),
            ],
            required_success_substrings=[
                "bpf_dynptr_from_xdp",
                "bpf_dynptr_slice",
            ],
            required_success_predicates=[
                ("direct packet precheck before dynptr", direct_packet_precheck_before_dynptr),
            ],
        )
    )
