#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def udp_packet(dport: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 28, 0, 0, 64, 17, 0, 0x0A000001, 0x0A000002)
    udp = struct.pack("!HHHH", 12345, dport, 8, 0)
    return eth + ip + udp


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "pointer arithmetic with <<= operator prohibited",
            ],
            functional_tests=[
                ("udp_dns_drop", lambda: udp_packet(53), 1),
                ("udp_http_pass", lambda: udp_packet(80), 2),
            ],
        )
    )
