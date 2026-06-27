#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


ETH_P_IP = 0x0800
IPPROTO_UDP = 17
IPPROTO_TCP = 6
DNS_PORT = 53


def ipv4_packet(proto: int, payload: bytes, *, ihl_words: int = 5) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", ETH_P_IP)
    options = b"\x01\x02\x03\x04" * (ihl_words - 5)
    total_len = ihl_words * 4 + len(payload)
    ip = struct.pack(
        "!BBHHHBBHII",
        (4 << 4) | ihl_words,
        0,
        total_len,
        0,
        0,
        64,
        proto,
        0,
        0x0A000001,
        0x0A000002,
    )
    return eth + ip + options + payload


def udp_packet(dest_port: int, *, ihl_words: int = 5, truncate_to: int | None = None) -> bytes:
    udp = struct.pack("!HHHH", 10000, dest_port, 8, 0)
    if truncate_to is not None:
        udp = udp[:truncate_to]
    return ipv4_packet(IPPROTO_UDP, udp, ihl_words=ihl_words)


def tcp_packet() -> bytes:
    return ipv4_packet(IPPROTO_TCP, b"\x00" * 20)


def arp_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 28)


def udp_dest_load_after_variable_ihl_and_udp_bound(load_output: str) -> bool:
    in_annotated_trace = False
    saw_ihl_mask = False
    saw_variable_ihl_bound = False
    saw_udp_bound = False

    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue

        if re.search(r"\br\d+ &= 60\b", line):
            saw_ihl_mask = True
        if saw_ihl_mask and "if r" in line and "> r2" in line and "var_off=(0x0; 0x3c)" in line:
            saw_variable_ihl_bound = True
        if (
            saw_variable_ihl_bound
            and "if r" in line
            and "> r2" in line
            and "off=22" in line
            and "var_off=(0x0; 0x3c)" in line
        ):
            saw_udp_bound = True
        if saw_udp_bound and re.search(r"=\s*\*\(u16 \*\)\(r\d+ \+2\)", line):
            return True
    return False


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to packet",
                "R3 offset is outside of the packet",
            ],
            functional_tests=[
                ("udp_dns_drops", lambda: udp_packet(DNS_PORT), 1),
                ("udp_non_dns_passes", lambda: udp_packet(54), 2),
                ("udp_dns_ipv4_options_drops", lambda: udp_packet(DNS_PORT, ihl_words=6), 1),
                ("tcp_passes", tcp_packet, 2),
                ("truncated_udp_passes", lambda: udp_packet(DNS_PORT, truncate_to=2), 2),
                ("arp_passes", arp_packet, 2),
            ],
            required_success_predicates=[
                (
                    "UDP dest load happens after variable-IHL proof and UDP header bound",
                    udp_dest_load_after_variable_ihl_and_udp_bound,
                ),
            ],
        )
    )
