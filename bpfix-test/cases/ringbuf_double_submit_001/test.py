#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case, submitted_ringbuf_record_with_mark7_or_11


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def truncated_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb")


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "expected=ringbuf_mem",
            ],
            functional_tests=[
                ("ipv4_submits_once_and_drops", lambda: frame(0x0800), 1),
                ("arp_submits_once_and_passes", lambda: frame(0x0806), 2),
                ("truncated_passes", truncated_packet, 2),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("submit mark=7 or mark=11 record", submitted_ringbuf_record_with_mark7_or_11),
            ],
        )
    )
