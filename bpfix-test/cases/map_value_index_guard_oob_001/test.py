#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def truncated_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb")


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to map value",
            ],
            functional_tests=[
                ("selector0_drops_from_slot0", lambda: frame(0x0800), 1),
                ("selector2_passes_from_slot1", lambda: frame(0x0802), 2),
                ("selector5_drops_from_slot2", lambda: frame(0x0805), 1),
                ("selector1_is_unmanaged_and_passes", lambda: frame(0x0801), 2),
                ("selector6_is_unmanaged_and_passes", lambda: frame(0x0806), 2),
                ("truncated_passes", truncated_packet, 2),
            ],
            required_success_substrings=[
                "map 'configs': found type = 1",
                "call bpf_map_lookup_elem#1",
            ],
            map_updates=[
                ("configs", struct.pack("<I", 0), struct.pack("<III", 1, 0, 1)),
            ],
        )
    )
