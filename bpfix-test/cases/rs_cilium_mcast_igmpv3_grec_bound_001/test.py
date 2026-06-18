#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import packet_register_state_updates, packet_state_has_variable_offset, run_case


MDNS_GROUP = 0xE00000FB
IGMPV3_REPORT = 0x22
IGMPV3_CHANGE_TO_INCLUDE = 3
IGMPV3_CHANGE_TO_EXCLUDE = 4


def ipv4_packet(proto: int, payload: bytes, *, ihl_words: int = 5, total_len: int | None = None) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    options = b"\x01\x02\x03\x04" * (ihl_words - 5)
    if total_len is None:
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
        0xE00000FB,
    )
    return eth + ip + options + payload


def grec(record_type: int, group: int) -> bytes:
    return struct.pack("!BBHI", record_type, 0, 0, group)


def igmpv3_report(records: list[bytes], *, truncate_record_to: int | None = None) -> bytes:
    header = struct.pack("!BBHHH", IGMPV3_REPORT, 0, 0, 0, len(records))
    body = b"".join(records)
    if truncate_record_to is not None:
        body = body[:truncate_record_to]
    return header + body


def igmpv3_packet(records: list[bytes], *, ihl_words: int = 5, truncate_record_to: int | None = None) -> bytes:
    return ipv4_packet(2, igmpv3_report(records, truncate_record_to=truncate_record_to), ihl_words=ihl_words)


def igmpv2_packet() -> bytes:
    return ipv4_packet(2, struct.pack("!BBHI", 0x16, 0, 0, MDNS_GROUP))


def udp_packet() -> bytes:
    return ipv4_packet(17, struct.pack("!HHHH", 10000, 53, 8, 0))


def arp_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 40)


def group_record_load_from_record_pointer(load_output: str) -> bool:
    in_annotated_trace = False
    packet_states: dict[str, str] = {}
    saw_ipv4_ihl_scale = False
    saw_ngrec_load = False
    saw_record_bound = False

    for line in load_output.splitlines():
        if not line.strip():
            packet_states = {}
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue

        if re.search(r"\br\d+\s*<<=\s*2\b", line):
            saw_ipv4_ihl_scale = True
        if saw_ipv4_ihl_scale and re.search(r"=\s*\*\(u16 \*\)\(r\d+\s*\+6\)", line):
            saw_ngrec_load = True

        current_updates = packet_register_state_updates(line)
        bound = re.search(r"\(2d\)\s+if r(\d+) > r2", line)
        if bound is not None and saw_ngrec_load:
            state = current_updates.get(bound.group(1)) or packet_states.get(bound.group(1))
            if state is not None and packet_state_has_variable_offset(state):
                saw_record_bound = True

        load = re.search(r"=\s*\*\(u32 \*\)\(r(\d+)\s*\+(\d+)\)", line)
        state = None
        if load is not None and saw_record_bound and int(load.group(2)) in {12, 20, 28, 36}:
            state = current_updates.get(load.group(1)) or packet_states.get(load.group(1))
        if state is not None and packet_state_has_variable_offset(state):
            return True

        for register, updated_state in current_updates.items():
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
                ("single_exclude_mdns_drops", lambda: igmpv3_packet([grec(IGMPV3_CHANGE_TO_EXCLUDE, MDNS_GROUP)]), 1),
                ("single_include_mdns_passes", lambda: igmpv3_packet([grec(IGMPV3_CHANGE_TO_INCLUDE, MDNS_GROUP)]), 2),
                ("exclude_other_group_passes", lambda: igmpv3_packet([grec(IGMPV3_CHANGE_TO_EXCLUDE, 0xE00000FC)]), 2),
                (
                    "second_record_exclude_mdns_drops",
                    lambda: igmpv3_packet(
                        [
                            grec(IGMPV3_CHANGE_TO_EXCLUDE, 0xE00000FC),
                            grec(IGMPV3_CHANGE_TO_EXCLUDE, MDNS_GROUP),
                        ]
                    ),
                    1,
                ),
                (
                    "truncated_record_passes",
                    lambda: igmpv3_packet([grec(IGMPV3_CHANGE_TO_EXCLUDE, MDNS_GROUP)], truncate_record_to=4),
                    2,
                ),
                (
                    "ipv4_options_exclude_mdns_drops",
                    lambda: igmpv3_packet([grec(IGMPV3_CHANGE_TO_EXCLUDE, MDNS_GROUP)], ihl_words=6),
                    1,
                ),
                ("igmpv2_passes", igmpv2_packet, 2),
                ("udp_passes", udp_packet, 2),
                ("arp_passes", arp_packet, 2),
            ],
            required_success_predicates=[
                (
                    "load IGMPv3 group address from record pointer after record bound",
                    group_record_load_from_record_pointer,
                ),
            ],
        )
    )
