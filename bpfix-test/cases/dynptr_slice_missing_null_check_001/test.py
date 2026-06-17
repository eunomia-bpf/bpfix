#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def short_packet() -> bytes:
    return bytes.fromhex("00112233")


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'rdonly_mem_or_null'",
            ],
            functional_tests=[
                ("ipv4_drops", lambda: frame(0x0800), 1),
                ("arp_passes", lambda: frame(0x0806), 2),
                ("short_packet_passes", short_packet, 2),
            ],
            required_success_substrings=[
                "bpf_dynptr_from_xdp",
                "bpf_dynptr_slice",
            ],
        )
    )
