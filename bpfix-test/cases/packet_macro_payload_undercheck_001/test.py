#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def udp_packet(check: int, *, truncate_udp_to: int | None = None) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 28, 0, 0, 64, 17, 0, 0x0A000001, 0x0A000002)
    udp = struct.pack("!HHHH", 10000, 53, 8, check)
    if truncate_udp_to is not None:
        udp = udp[:truncate_udp_to]
    return eth + ip + udp


def tcp_packet() -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 40, 0, 0, 64, 6, 0, 0x0A000001, 0x0A000002)
    return eth + ip + (b"\x00" * 20)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to packet",
            ],
            functional_tests=[
                ("marked_udp_drops", lambda: udp_packet(0xBEEF), 1),
                ("ordinary_udp_passes", lambda: udp_packet(0x1234), 2),
                ("truncated_udp_passes", lambda: udp_packet(0xBEEF, truncate_udp_to=7), 2),
                ("tcp_passes", tcp_packet, 2),
            ],
        )
    )
