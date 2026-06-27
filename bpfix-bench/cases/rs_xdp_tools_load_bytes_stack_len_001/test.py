#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import helper_reachable_with_register_value, run_case


def packet(window: bytes) -> bytes:
    return b"\xaa\xbb" + window + (b"\x00" * (18 - len(window)))


def two_stage_xdp_load_bytes(load_output: str) -> bool:
    helper_count = load_output.count("call bpf_xdp_load_bytes#189")
    return (
        helper_count >= 2
        and helper_reachable_with_register_value(load_output, "call bpf_xdp_load_bytes#189", "2", 2)
        and helper_reachable_with_register_value(load_output, "call bpf_xdp_load_bytes#189", "4", 12)
        and helper_reachable_with_register_value(load_output, "call bpf_xdp_load_bytes#189", "2", 14)
        and helper_reachable_with_register_value(load_output, "call bpf_xdp_load_bytes#189", "4", 6)
    )


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def load_lengths_use_stack_object_sizes(source: Path) -> bool:
    text = strip_comments(source.read_text(encoding="utf-8"))
    return (
        "bpf_xdp_load_bytes(ctx, WIRE_OFFSET, head, sizeof(head))" in text
        and "bpf_xdp_load_bytes(ctx, WIRE_OFFSET + sizeof(head), tail, sizeof(tail))" in text
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid write to stack",
            ],
            functional_tests=[
                ("magic_marker_drops", lambda: packet(b"B12345678XABCZ123!"), 1),
                ("wrong_middle_passes", lambda: packet(b"B123456789ABCZ123!"), 2),
                ("wrong_tail_passes", lambda: packet(b"B12345678XABCY123!"), 2),
                ("wrong_guard_passes", lambda: packet(b"B12345678XABCZ123?"), 2),
                ("wrong_head_passes", lambda: packet(b"A12345678XABCZ123!"), 2),
            ],
            required_success_substrings=[
                "call bpf_xdp_load_bytes#189",
            ],
            required_success_predicates=[
                ("xdp_load_bytes uses two bounded helper loads for the 18-byte wire window", two_stage_xdp_load_bytes),
            ],
            source_success_predicates=[
                ("case source invariant A", load_lengths_use_stack_object_sizes),
            ],
        )
    )
