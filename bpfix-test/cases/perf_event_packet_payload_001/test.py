#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import helper_calls_use_register_value, run_case


SAMPLE_BYTES = 18


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def truncated_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb")


def short_sample_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 3)


def perf_output_uses_stack_sample(load_output: str) -> bool:
    if "call bpf_probe_read_kernel#113" in load_output:
        return False
    if not helper_calls_use_register_value(load_output, "call bpf_perf_event_output#25", "5", SAMPLE_BYTES):
        return False
    window: list[str] = []
    in_annotated_trace = False
    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
            window = []
        if not in_annotated_trace:
            continue
        if not line.strip() or line.startswith("from "):
            window = []
            continue
        window.append(line)
        window = window[-8:]
        if "call bpf_perf_event_output#25" not in line:
            continue
        context = "\n".join(window)
        return "R4=fp" in context or "R4_w=fp" in context or "r4 += -" in context
    return False


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "helper access to the packet is not allowed",
            ],
            functional_tests=[
                ("ipv4_drops", lambda: frame(0x0800), 1),
                ("arp_passes", lambda: frame(0x0806), 2),
                ("short_sample_passes", short_sample_packet, 2),
                ("truncated_passes", truncated_packet, 2),
            ],
            required_success_substrings=[
                "call bpf_perf_event_output#25",
            ],
            required_success_predicates=[
                ("perf output uses a direct 18-byte stack sample", perf_output_uses_stack_sample),
            ],
        )
    )
