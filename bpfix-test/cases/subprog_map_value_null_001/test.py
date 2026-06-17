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
                "invalid mem access 'map_value_or_null'",
            ],
            functional_tests=[
                ("ipv4_drops_from_map", lambda: frame(0x0800), 1),
                ("arp_passes_from_map", lambda: frame(0x0806), 2),
                ("truncated_passes", truncated_packet, 2),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
                "map_value_or_null",
            ],
            required_success_predicates=[
                ("load drop_proto from map_value offset 0", loaded_map_value_u32_offset0),
            ],
            map_updates=[
                ("configs", struct.pack("<I", 0), struct.pack("<I", 0x0800)),
            ],
        )
    )
