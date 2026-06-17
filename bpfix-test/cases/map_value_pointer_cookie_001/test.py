#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import loaded_map_value_u32_offset0, run_case


def ipv4_packet(protocol: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20, 0, 0, 64, protocol, 0, 0x0A000001, 0x0A000002)
    return eth + ip


def non_ip_packet_with_tcp_protocol_offset() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 64))
    packet[23] = 6
    return bytes(packet)


def truncated_ipv4_packet_with_tcp_protocol_offset() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 19))
    packet[23] = 6
    return bytes(packet)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "pointer arithmetic with <<= operator prohibited",
            ],
            functional_tests=[
                ("tcp_drops_from_map_value", lambda: ipv4_packet(6), 1),
                ("udp_passes_from_map_value", lambda: ipv4_packet(17), 2),
                ("non_ip_pass_even_with_tcp_offset_byte", non_ip_packet_with_tcp_protocol_offset, 2),
                ("truncated_ipv4_pass_even_with_tcp_offset_byte", truncated_ipv4_packet_with_tcp_protocol_offset, 2),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
                "R0_w=map_value_or_null",
            ],
            required_success_predicates=[
                ("load drop_proto from map_value offset 0", loaded_map_value_u32_offset0),
            ],
            map_updates=[
                ("configs", struct.pack("<I", 0), struct.pack("<II", 6, 0)),
            ],
        )
    )
