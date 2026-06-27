#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import packet_register_state_updates
from bpf_case import packet_state_has_variable_offset
from bpf_case import run_case


def udp_packet(
    dport: int,
    *,
    checksum: int = 0x1234,
    tag: int | None = 0x42,
    ihl_words: int = 5,
    truncate_udp_to: int | None = None,
) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    options = b"\x01" * ((ihl_words - 5) * 4)
    payload = b"" if tag is None else bytes([tag])
    total_len = ihl_words * 4 + 8 + len(payload)
    ip = struct.pack(
        "!BBHHHBBHII",
        (4 << 4) | ihl_words,
        0,
        total_len,
        0,
        0,
        64,
        17,
        0,
        0x0A000001,
        0x0A000002,
    )
    udp = struct.pack("!HHHH", 10000, dport, 8, checksum)
    udp += payload
    if truncate_udp_to is not None:
        udp = udp[:truncate_udp_to]
    return eth + ip + options + udp


def tcp_packet() -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20, 0, 0, 64, 6, 0, 0x0A000001, 0x0A000002)
    return eth + ip + (b"\x00" * 20)


POLICY_KEY = struct.pack("<I", 0)


def dns_policy(checksum: int) -> bytes:
    return struct.pack("<HBB", checksum, 0x42, 0)


def udp_payload_tag_load_is_preserved(load_output: str) -> bool:
    in_annotated_trace = False
    saw_ihl_scale = False
    packet_states: dict[str, str] = {}

    for line in load_output.splitlines():
        if not line.strip():
            packet_states = {}
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue

        if re.search(r"\br\d+\s*<<=\s*2\b", line):
            saw_ihl_scale = True

        load = re.search(r"=\s*\*\(u8 \*\)\(r(\d+)(?:\s*\+\s*8)?\)", line)
        if load is not None and saw_ihl_scale:
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
                ("dns_udp_without_policy_passes", lambda: udp_packet(53), 2),
                ("dns_udp_drops", lambda: udp_packet(53), 1, [("policies", POLICY_KEY, dns_policy(0x1234))]),
                ("http_udp_passes", lambda: udp_packet(80), 2),
                ("dns_udp_wrong_checksum_passes", lambda: udp_packet(53, checksum=0x5678), 2),
                ("dns_udp_wrong_tag_passes", lambda: udp_packet(53, tag=0x99), 2),
                (
                    "options_dns_udp_drops",
                    lambda: udp_packet(53, ihl_words=6),
                    1,
                    [("policies", POLICY_KEY, dns_policy(0x1234))],
                ),
                ("truncated_udp_passes", lambda: udp_packet(53, truncate_udp_to=3), 2),
                ("truncated_udp_checksum_passes", lambda: udp_packet(53, truncate_udp_to=7), 2),
                ("dns_udp_no_payload_passes", lambda: udp_packet(53, tag=None), 2),
                ("tcp_passes", tcp_packet, 2),
            ],
            required_success_predicates=[
                ("UDP payload tag load uses IHL-derived packet pointer", udp_payload_tag_load_is_preserved),
            ],
        )
    )
