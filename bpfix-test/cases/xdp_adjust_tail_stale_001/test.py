#!/usr/bin/env python3
from __future__ import annotations

import struct
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def ipv4_udp_packet(dest_port: int, *, ihl_words: int = 5, udp_len: int = 8) -> bytes:
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
    udp = struct.pack("!HHHH", 10000, dest_port, 8, 0)[:udp_len]
    return eth + ip + options + udp + b"TAIL"


def ipv4_tcp_packet_with_dns_offset() -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 40, 0, 0, 64, 6, 0, 0x0A000001, 0x0A000002)
    tcp = bytearray(b"\x00" * 20)
    tcp[2:4] = struct.pack("!H", 53)
    return eth + ip + bytes(tcp) + b"TAIL"


def arp_packet_with_dns_offset() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 64))
    packet[36:38] = struct.pack("!H", 53)
    return bytes(packet)


def reloads_and_rechecks_eth_after_tail_adjust(load_output: str) -> bool:
    in_annotated_trace = False
    after_adjust = False
    saw_l2_bound = False

    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue

        if "call bpf_xdp_adjust_tail#65" in line:
            after_adjust = True
            saw_l2_bound = False
            continue
        if not after_adjust:
            continue

        if re.search(r"\br\d+\s*\+=\s*14\b", line) and "pkt(" in line:
            saw_l2_bound = False
            continue
        if re.search(r"\(2d\)\s+if r\d+ > r\d+", line) and "pkt(off=14" in line:
            saw_l2_bound = True
            continue
        if saw_l2_bound and re.search(r"=\s*\*\(u16 \*\)\(r\d+\s*\+12\)", line) and "pkt(" in line:
            return True
    return False


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access",
            ],
            functional_tests=[
                ("dns_udp_after_tail_trim_drops", lambda: ipv4_udp_packet(53), 1),
                ("ntp_udp_after_tail_trim_passes", lambda: ipv4_udp_packet(123), 2),
                ("dns_udp_options_after_tail_trim_drops", lambda: ipv4_udp_packet(53, ihl_words=6), 1),
                ("ntp_udp_options_after_tail_trim_passes", lambda: ipv4_udp_packet(123, ihl_words=6), 2),
                ("pre_trim_dns_but_post_trim_udp_incomplete_passes", lambda: ipv4_udp_packet(53, udp_len=4), 2),
                (
                    "pre_trim_options_dns_but_post_trim_udp_incomplete_passes",
                    lambda: ipv4_udp_packet(53, ihl_words=6, udp_len=4),
                    2,
                ),
                ("tcp_passes_even_with_dns_offset", ipv4_tcp_packet_with_dns_offset, 2),
                ("arp_passes_even_with_dns_offset", arp_packet_with_dns_offset, 2),
            ],
            required_success_substrings=[
                "call bpf_xdp_adjust_tail#65",
            ],
            required_success_predicates=[
                (
                    "reload data/data_end and recheck Ethernet after tail adjust",
                    reloads_and_rechecks_eth_after_tail_adjust,
                ),
            ],
        )
    )
