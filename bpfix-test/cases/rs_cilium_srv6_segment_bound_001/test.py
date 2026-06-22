#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import packet_register_state_updates
from bpf_case import run_case


DROP_TAG = 0xC1A01234


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


def udp_header(dport: int = 53) -> bytes:
    return struct.pack("!HHHH", 10000, dport, 8, 0)


def sid_with_tag(tag: int) -> bytes:
    return bytes.fromhex("20010db80000000000000000") + tag.to_bytes(4, "big")


def srv6_header(tag: int, *, typ: int = 4, segments_left: int = 1) -> bytes:
    fixed = bytes([17, 2, typ, segments_left, 0, 0, 0, 0])
    if segments_left == 0:
        return bytes([17, 0, typ, segments_left, 0, 0, 0, 0])
    return fixed + sid_with_tag(tag)


def srv6_drop_packet() -> bytes:
    return ipv6_packet(43, srv6_header(DROP_TAG) + udp_header())


def srv6_other_packet() -> bytes:
    return ipv6_packet(43, srv6_header(0xFACE1234) + udp_header())


def srv6_zero_left_packet() -> bytes:
    return ipv6_packet(43, srv6_header(DROP_TAG, segments_left=0) + udp_header())


def srv6_wrong_type_packet() -> bytes:
    return ipv6_packet(43, srv6_header(DROP_TAG, typ=0) + udp_header())


def srv6_truncated_segment_packet() -> bytes:
    return ipv6_packet(43, bytes([17, 2, 4, 1, 0, 0, 0, 0]), payload_len=8)


def ipv6_udp_packet() -> bytes:
    return ipv6_packet(17, udp_header())


def ipv4_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 48)


def first_sid_tag_load_is_preserved(load_output: str) -> bool:
    in_annotated_trace = False
    packet_states: dict[str, str] = {}
    saw_segment_bound = False

    for line in load_output.splitlines():
        if not line.strip():
            packet_states = {}
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue

        if re.search(r"\br\d+\s*\+=\s*(?:24|78)\b", line):
            saw_segment_bound = True

        load = re.search(r"=\s*\*\(u32 \*\)\(r(\d+)\s*\+\s*(?:12|20)\)", line)
        if load is not None and saw_segment_bound:
            state = packet_states.get(load.group(1), "")
            if "pkt" in state and "r=" in state:
                return True

        for register, updated_state in packet_register_state_updates(line).items():
            if updated_state is None:
                packet_states.pop(register, None)
            else:
                packet_states[register] = updated_state

    return False


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def first_segment_window_is_proved_before_srh_fields(source: Path) -> bool:
    text = strip_comments(source.read_text(encoding="utf-8"))
    bound = re.search(
        r"if\s*\(\s*\(\s*void\s*\*\s*\)\s*\(\s*srh\s*\+\s*1\s*\)\s*\+\s*sizeof\s*\(\s*struct\s+in6_addr\s*\)\s*>\s*data_end\s*\)",
        text,
    )
    type_use = text.find("srh->type")
    left_use = text.find("srh->segments_left")
    return bound is not None and type_use != -1 and left_use != -1 and bound.start() < type_use < left_use


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to packet",
            ],
            functional_tests=[
                ("srv6_matching_sid_drops", srv6_drop_packet, 1),
                ("srv6_nonmatching_sid_passes", srv6_other_packet, 2),
                ("srv6_segments_left_zero_passes", srv6_zero_left_packet, 2),
                ("srv6_wrong_type_passes", srv6_wrong_type_packet, 2),
                ("srv6_truncated_segment_passes", srv6_truncated_segment_packet, 2),
                ("ipv6_udp_without_routing_passes", ipv6_udp_packet, 2),
                ("ipv4_passes", ipv4_packet, 2),
            ],
            required_success_predicates=[
                ("first SID tag load after segment-list bound", first_sid_tag_load_is_preserved),
            ],
            source_success_predicates=[
                ("case source invariant A", first_segment_window_is_proved_before_srh_fields),
            ],
        )
    )
