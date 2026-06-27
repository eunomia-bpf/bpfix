#!/usr/bin/env python3
from __future__ import annotations

import struct
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case, xdp_adjust_head_called_with_delta14


def ipv4_udp_packet(dest_port: int, *, ihl_words: int = 5, udp_len: int = 9, marker: int = 0x42) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    options = b"\x01\x02\x03\x04" * (ihl_words - 5)
    ip_len = ihl_words * 4
    ip = struct.pack(
        "!BBHHHBBHII",
        (4 << 4) | ihl_words,
        0,
        ip_len + udp_len,
        0,
        0,
        64,
        17,
        0,
        0x0A000001,
        0x0A000002,
    )
    udp = struct.pack("!HHHH", 10000, dest_port, 8, 0) + bytes([marker])
    return eth + ip + options + udp[:udp_len]


def ipv4_tcp_packet_with_dns_offset() -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 40, 0, 0, 64, 6, 0, 0x0A000001, 0x0A000002)
    tcp = bytearray(b"\x00" * 20)
    tcp[2:4] = struct.pack("!H", 53)
    return eth + ip + bytes(tcp)


def arp_packet_with_dns_offset() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 64))
    packet[36:38] = struct.pack("!H", 53)
    return bytes(packet)


def reloads_and_checks_udp_after_head_adjust(load_output: str) -> bool:
    in_annotated_trace = False
    after_adjust = False
    saw_ihl_mask = False
    saw_udp_bound = False

    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue
        if "call bpf_xdp_adjust_head#44" in line:
            after_adjust = True
            continue
        if not after_adjust:
            continue
        if re.search(r"\br\d+ &= 60\b", line):
            saw_ihl_mask = True
        if saw_ihl_mask and "if r" in line and "> r" in line and "off=8" in line:
            saw_udp_bound = True
        if saw_udp_bound and re.search(r"=\s*\*\(u16 \*\)\(r\d+ \+2\)", line):
            return True
    return False


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "R6 invalid mem access 'scalar'",
            ],
            functional_tests=[
                ("dns_udp_after_head_adjust_drops", lambda: ipv4_udp_packet(53), 1),
                ("dns_udp_wrong_marker_after_head_adjust_passes", lambda: ipv4_udp_packet(53, marker=0x41), 2),
                ("ntp_udp_after_head_adjust_passes", lambda: ipv4_udp_packet(123), 2),
                ("dns_udp_options_after_head_adjust_drops", lambda: ipv4_udp_packet(53, ihl_words=6), 1),
                (
                    "dns_udp_options_wrong_marker_after_head_adjust_passes",
                    lambda: ipv4_udp_packet(53, ihl_words=6, marker=0x41),
                    2,
                ),
                ("ntp_udp_options_after_head_adjust_passes", lambda: ipv4_udp_packet(123, ihl_words=6), 2),
                ("dns_udp_truncated_after_head_adjust_passes", lambda: ipv4_udp_packet(53, udp_len=4), 2),
                ("dns_udp_no_payload_after_head_adjust_passes", lambda: ipv4_udp_packet(53, udp_len=8), 2),
                (
                    "dns_udp_options_truncated_after_head_adjust_passes",
                    lambda: ipv4_udp_packet(53, ihl_words=6, udp_len=4),
                    2,
                ),
                ("tcp_passes_even_with_dns_offset", ipv4_tcp_packet_with_dns_offset, 2),
                ("arp_passes_even_with_dns_offset", arp_packet_with_dns_offset, 2),
            ],
            required_success_substrings=[
                "call bpf_xdp_adjust_head#44",
            ],
            required_success_predicates=[
                ("call bpf_xdp_adjust_head with delta 14", xdp_adjust_head_called_with_delta14),
                ("reload and check UDP dest after head adjust", reloads_and_checks_udp_after_head_adjust),
            ],
        )
    )
