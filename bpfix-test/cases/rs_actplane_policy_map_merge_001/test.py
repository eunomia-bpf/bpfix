#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case, loaded_map_value_u32_offset0, stored_map_value_u32_offset4


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 48)


def policy_value(proto: int) -> bytes:
    return proto.to_bytes(4, "little") + (0).to_bytes(4, "little")


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access",
            ],
            functional_tests=[
                (
                    "configured_ipv4_shot",
                    lambda: frame(0x0800),
                    2,
                    [("policy_map", (0).to_bytes(4, "little"), policy_value(0x0800))],
                ),
                (
                    "arp_ok",
                    lambda: frame(0x0806),
                    0,
                    [("policy_map", (0).to_bytes(4, "little"), policy_value(0x0800))],
                ),
                (
                    "configured_arp_shot",
                    lambda: frame(0x0806),
                    2,
                    [("policy_map", (0).to_bytes(4, "little"), policy_value(0x0806))],
                ),
                (
                    "ipv4_ok_when_arp_configured",
                    lambda: frame(0x0800),
                    0,
                    [("policy_map", (0).to_bytes(4, "little"), policy_value(0x0806))],
                ),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
            ],
            required_success_predicates=[
                ("loaded policy drop_proto from map value", loaded_map_value_u32_offset0),
                ("updated policy seen_ipv4 state", stored_map_value_u32_offset4),
            ],
            prog_type=None,
        )
    )
