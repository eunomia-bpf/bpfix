#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case, submitted_ringbuf_record_with_mark7


def ethernet_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 64)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "R0 invalid mem access 'ringbuf_mem_or_null'",
            ],
            functional_tests=[
                ("xdp_pass", ethernet_frame, 2),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "R0_w=ringbuf_mem_or_null",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("write mark=7 into submitted ringbuf_mem", submitted_ringbuf_record_with_mark7),
            ],
        )
    )
