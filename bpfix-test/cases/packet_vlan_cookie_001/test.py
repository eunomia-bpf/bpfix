#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17


def ipv4_packet(protocol: int, *, vlan: bool = False, tcp_dest_port: int = 80) -> bytes:
    eth_type = 0x8100 if vlan else 0x0800
    eth = bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", eth_type)
    vlan_hdr = struct.pack("!HH", 7, 0x0800) if vlan else b""
    payload = b""
    if protocol == IPPROTO_TCP:
        payload = struct.pack("!HHIIHHHH", 12345, tcp_dest_port, 0, 0, 5 << 12, 0, 0, 0)
    elif protocol == IPPROTO_UDP:
        payload = struct.pack("!HHHH", 12345, 443, 8, 0)
    elif protocol == IPPROTO_ICMP:
        payload = bytes.fromhex("0800000000000000")

    total_length = 20 + len(payload)
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, total_length, 0, 0, 64, protocol, 0, 0x0A000001, 0x0A000002)
    return eth + vlan_hdr + ip + payload


def tcp_packet(dest_port: int, *, vlan: bool = False) -> bytes:
    return ipv4_packet(IPPROTO_TCP, vlan=vlan, tcp_dest_port=dest_port)


def non_ip_packet_with_tls_offset_byte() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 80))
    packet[36:38] = struct.pack("!H", 443)
    return bytes(packet)


def truncated_vlan_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb8100") + b"\x00\x07"


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "pointer arithmetic with <<= operator prohibited",
            ],
            functional_tests=[
                ("plain_tcp_tls_drop", lambda: tcp_packet(443), 1),
                ("plain_tcp_http_pass", lambda: tcp_packet(80), 2),
                ("vlan_tcp_tls_drop", lambda: tcp_packet(443, vlan=True), 1),
                ("vlan_tcp_http_pass", lambda: tcp_packet(80, vlan=True), 2),
                ("vlan_udp_pass_even_with_tls_dest_port", lambda: ipv4_packet(IPPROTO_UDP, vlan=True), 2),
                ("vlan_icmp_pass", lambda: ipv4_packet(IPPROTO_ICMP, vlan=True), 2),
                ("non_ip_pass_even_with_tls_offset_byte", non_ip_packet_with_tls_offset_byte, 2),
                ("truncated_vlan_pass", truncated_vlan_packet, 2),
            ],
        )
    )
