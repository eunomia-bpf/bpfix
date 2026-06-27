#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case, submitted_ringbuf_record_with_mark7, xdp_adjust_head_called_with_delta14


def ipv4_packet(protocol: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20, 0, 0, 64, protocol, 0, 0x0A000001, 0x0A000002)
    return eth + ip


def non_ip_packet_with_udp_protocol_offset() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 64))
    packet[23] = 17
    return bytes(packet)


def truncated_ipv4_packet_with_udp_protocol_offset() -> bytes:
    packet = bytearray(bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 19))
    packet[23] = 17
    return bytes(packet)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def submit_after_post_adjust_recheck(source: Path) -> bool:
    text = strip_comments(source.read_text(encoding="utf-8"))
    adjust_pos = text.find("bpf_xdp_adjust_head")
    if adjust_pos == -1:
        return False
    after = text[adjust_pos:]
    submit_pos = after.find("bpf_ringbuf_submit")
    reload_data_pos = after.find("data = (void *)(long)ctx->data")
    reload_end_pos = after.find("data_end = (void *)(long)ctx->data_end")
    recheck = re.search(r"\bif\s*\([^;\n]*iph\s*\+\s*1[^;\n]*>\s*data_end\s*\)", after)
    if submit_pos == -1 or reload_data_pos == -1 or reload_end_pos == -1 or recheck is None:
        return False
    discard_pos = after.find("bpf_ringbuf_discard(rec, 0)", recheck.end(), submit_pos)
    return reload_data_pos < recheck.start() < submit_pos and reload_end_pos < recheck.start() and discard_pos != -1


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'scalar'",
            ],
            functional_tests=[
                ("udp_after_adjust_submits_and_drops", lambda: ipv4_packet(17), 1),
                ("tcp_after_adjust_submits_and_passes", lambda: ipv4_packet(6), 2),
                ("non_ip_pass_even_with_udp_offset_byte", non_ip_packet_with_udp_protocol_offset, 2),
                ("truncated_ipv4_pass_even_with_udp_offset_byte", truncated_ipv4_packet_with_udp_protocol_offset, 2),
            ],
            required_success_substrings=[
                "call bpf_xdp_adjust_head#44",
                "call bpf_ringbuf_reserve#131",
                "R0_w=ringbuf_mem_or_null",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("call bpf_xdp_adjust_head with delta 14", xdp_adjust_head_called_with_delta14),
                ("write mark=7 into submitted ringbuf_mem", submitted_ringbuf_record_with_mark7),
            ],
            source_success_predicates=[
                ("case source invariant A", submit_after_post_adjust_recheck),
            ],
        )
    )
