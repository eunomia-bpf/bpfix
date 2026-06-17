#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def fourteen_byte_ipv4_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800")


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to packet",
            ],
            functional_tests=[
                ("ipv4_drops_from_real_eth_type", lambda: frame(0x0800), 1),
                ("arp_passes_from_real_eth_type", lambda: frame(0x0806), 2),
                ("fourteen_byte_ipv4_frame_drops", fourteen_byte_ipv4_frame, 1),
            ],
        )
    )
