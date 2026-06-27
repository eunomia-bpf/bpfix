#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import (
    loaded_map_value_u32_offset,
    loaded_map_value_u32_offset0,
    lookup_pinned_map_value,
    run_case,
    stored_map_value_u32_offset,
    stored_map_value_u32_offset4,
)


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def config(drop_proto: int, seen_packets: int, pass_proto: int, key_xor: int) -> bytes:
    return struct.pack("<IIII", drop_proto, seen_packets, pass_proto, key_xor)


def frame(eth_type: int, *, selector: int = 0) -> bytes:
    dst = bytes([0, 0x11, 0x22, 0x33, 0x44, selector & 0xFF])
    return dst + bytes.fromhex("66778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def truncated_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb")


def config_value_matches(key: int, expected: bytes):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "configs", u32(key))
        return value == expected

    return check


def loaded_map_value_u32_offset8(load_output: str) -> bool:
    return loaded_map_value_u32_offset(load_output, 8)


def stored_map_value_u32_offset12(load_output: str) -> bool:
    return stored_map_value_u32_offset(load_output, 12)


BASE_MAP = [
    ("configs", u32(0), config(0x0800, 0, 0x86DD, 0)),
    ("configs", u32(1), config(0x0806, 0, 0x0800, 0)),
]


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'map_value_or_null'",
            ],
            functional_tests=[
                (
                    "key0_ipv4_drops_from_map",
                    lambda: frame(0x0800, selector=0),
                    1,
                    BASE_MAP,
                    [("key0 counter increments", config_value_matches(0, config(0x0800, 1, 0x86DD, 0)))],
                ),
                (
                    "key1_ipv4_passes_from_map",
                    lambda: frame(0x0800, selector=1),
                    2,
                    BASE_MAP,
                    [("key1 counter and xor update", config_value_matches(1, config(0x0806, 1, 0x0800, 1)))],
                ),
                (
                    "key1_arp_drops_from_map",
                    lambda: frame(0x0806, selector=1),
                    1,
                    BASE_MAP,
                    [("key1 arp counter and xor update", config_value_matches(1, config(0x0806, 1, 0x0800, 1)))],
                ),
                ("truncated_passes", truncated_packet, 2, BASE_MAP),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
                "map_value_or_null",
            ],
            required_success_predicates=[
                ("load drop_proto from map_value offset 0", loaded_map_value_u32_offset0),
                ("store seen_packets to map_value offset 4", stored_map_value_u32_offset4),
                ("load pass_proto from map_value offset 8", loaded_map_value_u32_offset8),
                ("store key_xor to map_value offset 12", stored_map_value_u32_offset12),
            ],
        )
    )
