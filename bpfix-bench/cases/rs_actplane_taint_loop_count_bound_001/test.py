#!/usr/bin/env python3
from __future__ import annotations

import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def packet(payload: bytes) -> bytes:
    return payload + (b"\x00" * (14 - len(payload)))


def loop_scan_reaches_marker_drop(load_output: str) -> bool:
    in_callback = False
    saw_bounded_index = False
    saw_stack_read = False
    saw_hit_update = False

    for line in load_output.splitlines():
        if line.startswith("from ") and " cb" in line:
            in_callback = True
        if not in_callback:
            continue
        if re.search(r"\bif r\d+ > 0x7 goto\b", line) or re.search(r"\br\d+ &= 7\b", line):
            saw_bounded_index = True
        if re.search(r"=\s*\*\(u8 \*\)\(r\d+ \+4\)", line):
            saw_stack_read = True
        if re.search(r"\*\(u32 \*\)\(r\d+ \+0\) = r\d+", line):
            saw_hit_update = True

    return "call bpf_loop#181" in load_output and saw_bounded_index and saw_stack_read and saw_hit_update


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid unbounded variable-offset read from stack",
            ],
            functional_tests=[
                ("single_marker_wraps_and_drops", lambda: packet(b"\x00\x01\xaa\x03\x04\x05\x06\x07"), 1),
                ("no_marker_passes", lambda: packet(b"\x00\x01\x02\x03\x04\x05\x06\x07"), 2),
                ("late_marker_passes", lambda: packet(b"\x00\x01\x02\x03\x04\x05\x06\x07\xaa"), 2),
            ],
            required_success_substrings=[
                "call bpf_loop#181",
            ],
            required_success_predicates=[
                ("loop callback scan remains in the accepted program", loop_scan_reaches_marker_drop),
            ],
        )
    )
