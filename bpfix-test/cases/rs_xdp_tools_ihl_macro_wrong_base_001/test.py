#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import packet_u16_load_from_variable_offset, run_case


def udp_packet(dport: int, *, ihl_words: int = 5, truncate_udp_to: int | None = None) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    options = b"\x01\x02\x03\x04" * (ihl_words - 5)
    total_len = ihl_words * 4 + 8
    ip = struct.pack(
        "!BBHHHBBHII",
        (4 << 4) | ihl_words,
        0,
        total_len,
        0,
        0,
        64,
        17,
        0,
        0x0A000001,
        0x0A000002,
    )
    udp = struct.pack("!HHHH", 10000, dport, 8, 0)
    if truncate_udp_to is not None:
        udp = udp[:truncate_udp_to]
    return eth + ip + options + udp


def tcp_packet() -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 40, 0, 0, 64, 6, 0, 0x0A000001, 0x0A000002)
    return eth + ip + (b"\x00" * 20)


def arp_packet_with_dns_at_fixed_l4() -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0806")
    return eth + (b"\x00" * 22) + struct.pack("!H", 53) + (b"\x00" * 20)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to packet",
            ],
            functional_tests=[
                ("udp_dns_drops", lambda: udp_packet(53), 1),
                ("udp_ntp_passes", lambda: udp_packet(123), 2),
                ("udp_options_dns_drops", lambda: udp_packet(53, ihl_words=6), 1),
                ("udp_options_ntp_passes", lambda: udp_packet(123, ihl_words=6), 2),
                ("truncated_udp_passes", lambda: udp_packet(53, truncate_udp_to=3), 2),
                ("tcp_passes", tcp_packet, 2),
                ("arp_passes_even_with_dns_fixed_offset", arp_packet_with_dns_at_fixed_l4, 2),
            ],
            required_success_predicates=[
                (
                    "load UDP destination from variable IHL-derived packet pointer",
                    packet_u16_load_from_variable_offset,
                ),
            ],
        )
    )
