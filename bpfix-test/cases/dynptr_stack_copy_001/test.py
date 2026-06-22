#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def ipv4_packet(protocol: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20, 0, 0, 64, protocol, 0, 0x0A000001, 0x0A000002)
    return eth + ip + (b"\x00" * 32)


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 84)


def short_packet() -> bytes:
    return bytes.fromhex("00112233")


def direct_packet_precheck_before_dynptr(load_output: str) -> bool:
    call = load_output.find("call bpf_dynptr_from_xdp")
    if call == -1:
        return False
    before = load_output[:call]
    return (
        "*(u32 *)(r1 +4)" in before
        and "*(u32 *)(r1 +0)" in before
        and "+= 34" in before
        and re.search(r"\(2d\) if r\d+ > r\d+ goto", before) is not None
    )


def two_dynptr_slices(load_output: str) -> bool:
    return load_output.count("call bpf_dynptr_slice#") >= 2


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "dynptr",
            ],
            functional_tests=[
                ("ipv4_udp_drops", lambda: ipv4_packet(17), 1),
                ("ipv4_tcp_passes", lambda: ipv4_packet(6), 2),
                ("arp_passes", lambda: frame(0x0806), 2),
                ("short_packet_passes", short_packet, 2),
            ],
            required_success_substrings=[
                "bpf_dynptr_from_xdp",
                "bpf_dynptr_slice",
            ],
            required_success_predicates=[
                ("direct packet precheck before dynptr helper", direct_packet_precheck_before_dynptr),
                ("two dynptr slices are preserved", two_dynptr_slices),
            ],
        )
    )
