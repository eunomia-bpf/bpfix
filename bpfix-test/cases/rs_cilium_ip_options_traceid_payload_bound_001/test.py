#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import packet_register_state_updates
from bpf_case import packet_state_has_variable_offset
from bpf_case import run_case


def ipv4_packet(ihl_words: int, protocol: int, payload: bytes) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb") + (0x0800).to_bytes(2, "big")
    total_len = ihl_words * 4 + len(payload)
    ip = bytes(
        [
            (4 << 4) | ihl_words,
            0,
            (total_len >> 8) & 0xff,
            total_len & 0xff,
            0,
            0,
            0,
            0,
            64,
            protocol,
            0,
            0,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
        ]
    )
    return eth + ip + payload


def udp_payload() -> bytes:
    return (10000).to_bytes(2, "big") + (53).to_bytes(2, "big") + b"\0\0\0\0"


def trace_opt16(value: int) -> bytes:
    return bytes([0x9E, 4]) + value.to_bytes(2, "big")


def trace_opt32(value: int) -> bytes:
    return bytes([0x9E, 6]) + value.to_bytes(4, "big")


def trace_opt64(value: int) -> bytes:
    return bytes([0x9E, 10]) + value.to_bytes(8, "big")


def noop_then_trace(value: int) -> bytes:
    return bytes([1]) + trace_opt16(value) + b"\0\0\0"


def no_options_udp() -> bytes:
    return ipv4_packet(5, 17, udp_payload())


def trace16_dns_drop() -> bytes:
    return ipv4_packet(6, 17, trace_opt16(0x1234) + udp_payload())


def trace16_other_pass() -> bytes:
    return ipv4_packet(6, 17, trace_opt16(0x4567) + udp_payload())


def trace32_dns_drop() -> bytes:
    return ipv4_packet(7, 17, trace_opt32(0x1234) + b"\0\0" + udp_payload())


def trace32_other_pass() -> bytes:
    return ipv4_packet(7, 17, trace_opt32(0x4567) + b"\0\0" + udp_payload())


def trace64_dns_drop() -> bytes:
    return ipv4_packet(8, 17, trace_opt64(0x1234) + b"\0\0" + udp_payload())


def trace64_other_pass() -> bytes:
    return ipv4_packet(8, 17, trace_opt64(0x4567) + b"\0\0" + udp_payload())


def noop_trace16_drop() -> bytes:
    return ipv4_packet(7, 17, noop_then_trace(0x1234) + udp_payload())


def unsupported_len_pass() -> bytes:
    return ipv4_packet(6, 17, bytes([0x9E, 3, 0]) + b"\0" + udp_payload())


def tcp_trace_pass() -> bytes:
    return ipv4_packet(6, 6, trace_opt16(0x1234) + (b"\0" * 8))


def variable_option_payload_load_is_preserved(load_output: str) -> bool:
    in_annotated_trace = False
    packet_states: dict[str, str] = {}
    saw_loop_derived_increment = False

    for line in load_output.splitlines():
        if not line.strip():
            packet_states = {}
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue

        if re.search(r"\br\d+\s*\+=\s*r\d+\b", line):
            saw_loop_derived_increment = True

        load = re.search(r"=\s*\*\(u16 \*\)\(r(\d+)(?:\s*\+\s*0)?\)", line)
        if load is not None and saw_loop_derived_increment:
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
                ("no_options_udp_passes", no_options_udp, 2),
                ("trace16_dns_drops", trace16_dns_drop, 1),
                ("trace16_other_passes", trace16_other_pass, 2),
                ("trace32_dns_drops", trace32_dns_drop, 1),
                ("trace32_other_passes", trace32_other_pass, 2),
                ("trace64_dns_drops", trace64_dns_drop, 1),
                ("trace64_other_passes", trace64_other_pass, 2),
                ("noop_trace16_drops", noop_trace16_drop, 1),
                ("unsupported_len_passes", unsupported_len_pass, 2),
                ("tcp_trace_passes", tcp_trace_pass, 2),
            ],
            required_success_predicates=[
                (
                    "trace-id load uses loop-derived option pointer",
                    variable_option_payload_load_is_preserved,
                ),
            ],
        )
    )
