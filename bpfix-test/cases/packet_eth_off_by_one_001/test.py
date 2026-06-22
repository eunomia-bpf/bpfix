#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def eth_header_only(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big")


def ipv6_frame(next_header: int) -> bytes:
    payload = bytearray(b"\x00" * 64)
    payload[6] = next_header
    return bytes.fromhex("00112233445566778899aabb86dd") + bytes(payload)


def thirteen_byte_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb08")


def twenty_byte_ipv6_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb86dd") + (b"\x00" * 6)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to packet",
            ],
            functional_tests=[
                ("ipv4_drops", lambda: frame(0x0800), 1),
                ("ipv4_eth_header_only_drops", lambda: eth_header_only(0x0800), 1),
                ("arp_passes", lambda: frame(0x0806), 2),
                ("ipv6_udp_drops", lambda: ipv6_frame(17), 1),
                ("ipv6_tcp_passes", lambda: ipv6_frame(6), 2),
                ("thirteen_byte_packet_passes", thirteen_byte_packet, 2),
                ("twenty_byte_ipv6_packet_passes", twenty_byte_ipv6_packet, 2),
            ],
        )
    )
