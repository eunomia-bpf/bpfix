#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import packet_eth_proto_store_after_skb_change_proto, run_case


def ipv6_frame(next_header: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb") + (0x86DD).to_bytes(2, "big")
    version_tc_flow = (6 << 28).to_bytes(4, "big")
    payload_len = (8).to_bytes(2, "big")
    hdr = (
        version_tc_flow
        + payload_len
        + bytes([next_header, 64])
        + bytes.fromhex("20010db8000000000000000000000001")
        + bytes.fromhex("20010db8000000000000000000000002")
    )
    return eth + hdr + (b"\x00" * 48)


def ipv4_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + (0x0800).to_bytes(2, "big") + (b"\x00" * 48)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access",
            ],
            functional_tests=[
                ("ipv6_udp_rewrite_shot", lambda: ipv6_frame(17), 2),
                ("ipv6_tcp_ok", lambda: ipv6_frame(6), 0),
                ("ipv4_ok", ipv4_frame, 0),
            ],
            required_success_substrings=[
                "call bpf_skb_change_proto#31",
            ],
            required_success_predicates=[
                (
                    "stored IPv4 ethertype through a reloaded packet pointer after bpf_skb_change_proto",
                    packet_eth_proto_store_after_skb_change_proto,
                ),
            ],
            prog_type=None,
        )
    )
