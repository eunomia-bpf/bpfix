#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case, xdp_adjust_head_called_with_delta14


def ipv4_packet(protocol: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20, 0, 0, 64, protocol, 0, 0x0A000001, 0x0A000002)
    return eth + ip


def non_ip_packet_with_udp_protocol_byte() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 64))
    packet[23] = 17
    return bytes(packet)


def truncated_ip_packet_with_udp_protocol_byte() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 19))
    packet[23] = 17
    return bytes(packet)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "R6 invalid mem access 'scalar'",
            ],
            functional_tests=[
                ("udp_after_adjust_drop", lambda: ipv4_packet(17), 1),
                ("tcp_after_adjust_pass", lambda: ipv4_packet(6), 2),
                ("non_ip_pass_even_with_udp_offset_byte", non_ip_packet_with_udp_protocol_byte, 2),
                ("truncated_ip_pass_even_with_udp_offset_byte", truncated_ip_packet_with_udp_protocol_byte, 2),
            ],
            required_success_substrings=[
                "call bpf_xdp_adjust_head#44",
            ],
            required_success_predicates=[
                ("call bpf_xdp_adjust_head with delta 14", xdp_adjust_head_called_with_delta14),
            ],
        )
    )
