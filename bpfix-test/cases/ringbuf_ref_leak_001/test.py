#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import discarded_ringbuf_record_with_mark7, run_case, submitted_ringbuf_record_with_mark7


def ethernet_frame_with_first_byte(value: int) -> bytes:
    return bytes([value]) + bytes.fromhex("112233445566778899aabb0800") + (b"\x00" * 64)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "Unreleased reference id=",
                "reference leak",
            ],
            functional_tests=[
                ("xdp_drop_after_discard_branch", lambda: ethernet_frame_with_first_byte(0), 1),
                ("xdp_pass_after_submit_branch", lambda: ethernet_frame_with_first_byte(1), 2),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "R0_w=ringbuf_mem_or_null",
                "call bpf_ringbuf_discard#133",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("discard mark=7 ringbuf_mem on early branch", discarded_ringbuf_record_with_mark7),
                ("submit mark=7 ringbuf_mem on normal branch", submitted_ringbuf_record_with_mark7),
            ],
        )
    )
