#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def udp_packet(dest_port: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 28, 0, 0, 64, 17, 0, 0x0A000001, 0x0A000002)
    udp = struct.pack("!HHHH", 12345, dest_port, 8, 0)
    return eth + ip + udp


def tcp_packet(dest_port: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 40, 0, 0, 64, 6, 0, 0x0A000001, 0x0A000002)
    tcp = struct.pack("!HHIIHHHH", 12345, dest_port, 0, 0, 5 << 12, 0, 0, 0)
    return eth + ip + tcp


def icmp_packet_with_dns_offset_byte() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0800"))
    packet += struct.pack("!BBHHHBBHII", 0x45, 0, 40, 0, 0, 64, 1, 0, 0x0A000001, 0x0A000002)
    packet += b"\x00" * 20
    packet[36:38] = struct.pack("!H", 53)
    return bytes(packet)


def truncated_udp_packet_with_dns_offset_byte() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0800"))
    packet += struct.pack("!BBHHHBBHII", 0x45, 0, 28, 0, 0, 64, 17, 0, 0x0A000001, 0x0A000002)
    packet += b"\x00\x35\x00"
    return bytes(packet)


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
                ("tcp_tls_drop", lambda: tcp_packet(443), 1),
                ("tcp_http_pass", lambda: tcp_packet(80), 2),
                ("icmp_pass_even_with_dns_offset_byte", icmp_packet_with_dns_offset_byte, 2),
                ("truncated_udp_header_pass", truncated_udp_packet_with_dns_offset_byte, 2),
            ],
        )
    )
