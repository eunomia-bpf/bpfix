#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def frame(index_byte: int) -> bytes:
    dest = bytes([0, 0x11, 0x22, 0x33, 0x44, index_byte & 0xFF])
    return dest + bytes.fromhex("66778899aabb0800") + (b"\x00" * 64)


def truncated_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb")


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "unbounded min value",
            ],
            functional_tests=[
                ("slot0_drops", lambda: frame(0), 1),
                ("slot1_passes", lambda: frame(1), 2),
                ("negative_index_passes", lambda: frame(0xFF), 2),
                ("truncated_passes", truncated_packet, 2),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
            ],
            map_updates=[
                ("configs", struct.pack("<I", 0), struct.pack("<II", 1, 0)),
            ],
        )
    )
