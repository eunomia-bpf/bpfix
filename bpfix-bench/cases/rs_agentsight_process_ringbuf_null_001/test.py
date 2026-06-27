#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import ringbuf_written_refs_before_helper, run_case


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 48)


def submitted_process_event_mark7(load_output: str) -> bool:
    return ringbuf_written_refs_before_helper(
        load_output,
        "call bpf_ringbuf_submit#132",
        expected_u32_values={7},
        expected_store_offset=12,
        expected_ringbuf_size=16,
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access",
            ],
            functional_tests=[
                ("ipv4_shot", lambda: frame(0x0800), 2),
                ("arp_ok", lambda: frame(0x0806), 0),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("submitted 16-byte process event mark=7", submitted_process_event_mark7),
            ],
            prog_type=None,
        )
    )
