#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case, ringbuf_reserve_reachable_with_mark7, submitted_ringbuf_record_with_mark11


def ipv4_packet(protocol: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20, 0, 0, 64, protocol, 0, 0x0A000001, 0x0A000002)
    return eth + ip


def non_ip_packet_with_udp_protocol_offset() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 64))
    packet[23] = 17
    return bytes(packet)


def truncated_ipv4_packet_with_udp_protocol_offset() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 19))
    packet[23] = 17
    return bytes(packet)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def preserves_shadow_cookie_without_pointer_arithmetic(source: Path) -> bool:
    text = strip_comments(source.read_text(encoding="utf-8"))
    return (
        "asm volatile" not in text
        and re.search(r"\b__u64\s+cookie\s*=\s*\(\s*__u64\s*\)\s*\(\s*long\s*\)\s*rec\s*;", text) is not None
        and re.search(r"\bstruct\s+event\s*\*\s*shadow\s*=\s*\(\s*void\s*\*\s*\)\s*\(\s*long\s*\)\s*cookie\s*;", text) is not None
        and re.search(r"\bbpf_ringbuf_submit\s*\(\s*shadow\s*,\s*0\s*\)", text) is not None
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "pointer arithmetic with <<= operator prohibited",
            ],
            functional_tests=[
                ("udp_submits_mark7_and_drops", lambda: ipv4_packet(17), 1),
                ("tcp_submits_mark11_and_passes", lambda: ipv4_packet(6), 2),
                ("non_ip_pass_even_with_udp_offset_byte", non_ip_packet_with_udp_protocol_offset, 2),
                ("truncated_ipv4_pass_even_with_udp_offset_byte", truncated_ipv4_packet_with_udp_protocol_offset, 2),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "ringbuf_mem_or_null",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("mark=7 branch reaches ringbuf reserve", ringbuf_reserve_reachable_with_mark7),
                ("write mark=11 into submitted ringbuf_mem", submitted_ringbuf_record_with_mark11),
            ],
            source_success_predicates=[
                ("case source invariant A", preserves_shadow_cookie_without_pointer_arithmetic),
            ],
        )
    )
