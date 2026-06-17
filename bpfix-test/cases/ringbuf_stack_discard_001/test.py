#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import discarded_ringbuf_record_with_mark7, run_case


def ethernet_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 64)


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "expected=ringbuf_mem",
            ],
            functional_tests=[
                ("xdp_pass", ethernet_frame, 2),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "call bpf_ringbuf_discard#133",
            ],
            required_success_predicates=[
                ("discard mark=7 record", discarded_ringbuf_record_with_mark7),
            ],
        )
    )
