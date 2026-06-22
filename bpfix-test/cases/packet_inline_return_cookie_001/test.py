#!/usr/bin/env python3
from __future__ import annotations

import re
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


def tcp_packet_with_dns_offset_byte() -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 40, 0, 0, 64, 6, 0, 0x0A000001, 0x0A000002)
    tcp = bytearray(b"\x00" * 20)
    tcp[2:4] = struct.pack("!H", 53)
    return eth + ip + bytes(tcp)


def truncated_udp_packet_with_dns_offset_byte() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0800"))
    packet += struct.pack("!BBHHHBBHII", 0x45, 0, 28, 0, 0, 64, 17, 0, 0x0A000001, 0x0A000002)
    packet += b"\x00\x00\x00"
    return bytes(packet)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def preserves_cookie_alias_without_pointer_arithmetic(source: Path) -> bool:
    text = strip_comments(source.read_text(encoding="utf-8"))
    return (
        "asm volatile" not in text
        and re.search(r"\b__u64\s+cookie\s*=\s*\(\s*__u64\s*\)\s*\(\s*long\s*\)\s*udp\s*;", text) is not None
        and re.search(r"\budp\s*=\s*\(\s*struct\s+udphdr\s*\*\s*\)\s*\(\s*long\s*\)\s*cookie\s*;", text) is not None
    )


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
                ("tcp_pass_even_with_dns_offset_byte", tcp_packet_with_dns_offset_byte, 2),
                ("truncated_udp_header_pass", truncated_udp_packet_with_dns_offset_byte, 2),
            ],
            source_success_predicates=[
                ("case source invariant A", preserves_cookie_alias_without_pointer_arithmetic),
            ],
        )
    )
