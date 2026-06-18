#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import packet_register_state_updates, packet_state_has_variable_offset, run_case


def ipv6_packet(next_header: int, payload: bytes, *, payload_len: int | None = None) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb86dd")
    version_tc_flow = (6 << 28).to_bytes(4, "big")
    if payload_len is None:
        payload_len = len(payload)
    hdr = (
        version_tc_flow
        + payload_len.to_bytes(2, "big")
        + bytes([next_header, 64])
        + bytes.fromhex("20010db8000000000000000000000001")
        + bytes.fromhex("20010db8000000000000000000000002")
    )
    return eth + hdr + payload


def udp_header(dport: int) -> bytes:
    return struct.pack("!HHHH", 10000, dport, 8, 0)


def ipv6_udp_packet(dport: int) -> bytes:
    return ipv6_packet(17, udp_header(dport))


def ipv6_hopopts_udp_packet(dport: int) -> bytes:
    hopopts = bytes([17, 0]) + (b"\x00" * 6)
    return ipv6_packet(0, hopopts + udp_header(dport))


def truncated_hopopts_packet() -> bytes:
    return ipv6_packet(0, bytes([17]), payload_len=1)


def ipv6_tcp_packet() -> bytes:
    return ipv6_packet(6, b"\x00" * 20)


def ipv4_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 48)


def udp_dest_load_from_extension_derived_l4(load_output: str) -> bool:
    in_annotated_trace = False
    packet_states: dict[str, str] = {}
    saw_extension_scale = False

    for line in load_output.splitlines():
        if not line.strip():
            packet_states = {}
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue

        if re.search(r"\br\d+\s*<<=\s*3\b", line):
            saw_extension_scale = True

        load = re.search(r"=\s*\*\(u16 \*\)\(r(\d+)\s*\+\s*2\)", line)
        if load is not None and saw_extension_scale:
            state = packet_states.get(load.group(1))
            if state is not None and packet_state_has_variable_offset(state):
                return True

        for register, updated_state in packet_register_state_updates(line).items():
            if updated_state is None:
                packet_states.pop(register, None)
            else:
                packet_states[register] = updated_state
    return False


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to packet",
            ],
            functional_tests=[
                ("ipv6_udp_dns_drops", lambda: ipv6_udp_packet(53), 1),
                ("ipv6_udp_ntp_passes", lambda: ipv6_udp_packet(123), 2),
                ("hopopts_udp_dns_drops", lambda: ipv6_hopopts_udp_packet(53), 1),
                ("hopopts_udp_ntp_passes", lambda: ipv6_hopopts_udp_packet(123), 2),
                ("truncated_hopopts_passes", truncated_hopopts_packet, 2),
                ("ipv6_tcp_passes", ipv6_tcp_packet, 2),
                ("ipv4_passes", ipv4_packet, 2),
            ],
            required_success_predicates=[
                (
                    "load UDP destination from extension-derived variable L4 pointer",
                    udp_dest_load_from_extension_derived_l4,
                ),
            ],
        )
    )
