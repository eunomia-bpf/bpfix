#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import (
    loaded_map_value_u32_offset0,
    loaded_map_value_u32_offset4,
    run_case,
    stored_map_value_u32_offset4,
)


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


def map_value(drop_proto: int, seen_packets: int = 0) -> bytes:
    return struct.pack("<II", drop_proto, seen_packets)


CONFIG_KEY0 = struct.pack("<I", 0)
CONFIG_KEY_TCP = struct.pack("<I", 6)
CONFIG_KEY_UDP = struct.pack("<I", 17)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'map_value_or_null'",
            ],
            functional_tests=[
                ("tcp_drops_from_default_when_override_missing", lambda: ipv4_packet(6), 1, [("configs", CONFIG_KEY0, map_value(6))]),
                (
                    "tcp_passes_when_override_changes_policy",
                    lambda: ipv4_packet(6),
                    2,
                    [("configs", CONFIG_KEY0, map_value(6)), ("configs", CONFIG_KEY_TCP, map_value(17))],
                ),
                ("udp_drops_from_default_when_override_missing", lambda: ipv4_packet(17), 1, [("configs", CONFIG_KEY0, map_value(17))]),
                (
                    "udp_passes_when_override_changes_policy",
                    lambda: ipv4_packet(17),
                    2,
                    [("configs", CONFIG_KEY0, map_value(17)), ("configs", CONFIG_KEY_UDP, map_value(6))],
                ),
                (
                    "non_ip_pass_even_with_tcp_offset_byte",
                    non_ip_packet_with_tcp_protocol_offset,
                    2,
                    [("configs", CONFIG_KEY0, map_value(6))],
                ),
                (
                    "truncated_ipv4_pass_even_with_tcp_offset_byte",
                    truncated_ipv4_packet_with_tcp_protocol_offset,
                    2,
                    [("configs", CONFIG_KEY0, map_value(6))],
                ),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
                "map_value_or_null",
            ],
            required_success_predicates=[
                ("load drop_proto from map_value offset 0", loaded_map_value_u32_offset0),
                ("load seen_packets from map_value offset 4", loaded_map_value_u32_offset4),
                ("store seen_packets to map_value offset 4", stored_map_value_u32_offset4),
            ],
        )
    )
