#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def packet(payload_len: int) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    return eth + (bytes([payload_len & 0xFF]) * payload_len)


def perf_output_uses_xdpdump_metadata(load_output: str) -> bool:
    in_annotated_trace = False
    saw_caplen_shift = False
    saw_stack_metadata = False
    saw_perf_helper = False

    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue
        if re.search(r"\br\d+\s*<<=\s*32\b", line):
            saw_caplen_shift = True
        if re.search(r"\*\(u(16|32) \*\)\(r10 -\d+\)\s*=", line):
            saw_stack_metadata = True
        if "call bpf_perf_event_output#25" in line:
            saw_perf_helper = True
            if not (saw_caplen_shift and saw_stack_metadata):
                return False

    return saw_perf_helper and saw_caplen_shift and saw_stack_metadata


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "cannot pass map_type 2 into func bpf_perf_event_output#25",
            ],
            functional_tests=[
                ("short_packet_passes", lambda: packet(8), 2),
                ("snaplen_packet_passes", lambda: packet(80), 2),
                ("ethernet_header_only_passes", lambda: packet(0), 2),
            ],
            required_success_substrings=[
                "call bpf_perf_event_output#25",
                "map=xdpdump_perf_ma",
            ],
            required_success_predicates=[
                ("perf output uses xdpdump stack metadata and caplen flags", perf_output_uses_xdpdump_metadata),
            ],
        )
    )
