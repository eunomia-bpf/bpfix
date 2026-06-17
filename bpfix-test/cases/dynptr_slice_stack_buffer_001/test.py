#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def long_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 64)


def short_packet() -> bytes:
    return bytes.fromhex("00112233")


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid read from stack",
                "arg#2 arg#3 memory",
            ],
            functional_tests=[
                ("long_packet_drops", long_packet, 1),
                ("short_packet_passes", short_packet, 2),
            ],
            required_success_substrings=[
                "bpf_dynptr_from_xdp",
                "bpf_dynptr_slice",
            ],
        )
    )
