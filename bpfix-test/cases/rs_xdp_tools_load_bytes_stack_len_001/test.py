#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import helper_calls_use_register_value, run_case


def packet(prefix: bytes) -> bytes:
    return prefix + (b"\x00" * (14 - len(prefix)))


def xdp_load_bytes_uses_probe_len(load_output: str) -> bool:
    return helper_calls_use_register_value(load_output, "call bpf_xdp_load_bytes#189", "4", 10)


def marker_reads_use_loaded_stack_buffer(load_output: str) -> bool:
    helper = load_output.find("call bpf_xdp_load_bytes#189")
    first = load_output.find("*(u8 *)(r10 -1)", helper)
    tenth = load_output.find("*(u8 *)(r10 -10)", helper)
    return helper != -1 and first != -1 and tenth != -1 and helper < first < tenth


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid write to stack",
            ],
            functional_tests=[
                ("magic_marker_drops", lambda: packet(b"B12345678X"), 1),
                ("wrong_tail_passes", lambda: packet(b"B123456789"), 2),
                ("wrong_head_passes", lambda: packet(b"A12345678X"), 2),
            ],
            required_success_substrings=[
                "call bpf_xdp_load_bytes#189",
            ],
            required_success_predicates=[
                ("xdp_load_bytes helper uses the 10-byte probe stack buffer length", xdp_load_bytes_uses_probe_len),
                ("marker checks read bytes from the helper-filled stack buffer", marker_reads_use_loaded_stack_buffer),
            ],
        )
    )
