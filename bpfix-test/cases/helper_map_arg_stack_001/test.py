#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import loaded_map_value_u32_offset0, run_case


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def truncated_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb")


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "expected=map_ptr",
            ],
            functional_tests=[
                (
                    "ipv4_drops_from_ip_policy_map",
                    lambda: frame(0x0800),
                    1,
                    [("ip_configs", struct.pack("<I", 0), struct.pack("<I", 0x0800))],
                ),
                (
                    "arp_drops_from_arp_policy_map",
                    lambda: frame(0x0806),
                    1,
                    [("arp_configs", struct.pack("<I", 0), struct.pack("<I", 0x0806))],
                ),
                (
                    "ipv4_passes_when_only_arp_policy_drops",
                    lambda: frame(0x0800),
                    2,
                    [("ip_configs", struct.pack("<I", 0), struct.pack("<I", 0x0806))],
                ),
                ("ipv6_unmanaged_passes", lambda: frame(0x86DD), 2),
                ("truncated_passes", truncated_packet, 2),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
            ],
            required_success_predicates=[
                ("load drop_proto from map_value offset 0", loaded_map_value_u32_offset0),
            ],
        )
    )
