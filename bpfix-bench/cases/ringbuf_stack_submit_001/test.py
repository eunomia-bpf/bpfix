#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import (
    ringbuf_refs_written_with_u32_value,
    run_case,
    submitted_ringbuf_record_with_mark3_any_path,
    submitted_ringbuf_record_with_mark7_or_11,
    submitted_ringbuf_refs,
)


def ethernet_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 64)


def discarded_audit_mark3_record(log: str) -> bool:
    return bool(
        ringbuf_refs_written_with_u32_value(log, 3)
        & submitted_ringbuf_refs(log, helper_call="call bpf_ringbuf_discard#133")
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "R1 type=fp expected=ringbuf_mem",
            ],
            functional_tests=[
                ("xdp_pass", ethernet_frame, 2),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "R0_w=ringbuf_mem_or_null",
                "call bpf_ringbuf_discard#133",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("discard audit mark=3 ringbuf_mem on payload allocation failure", discarded_audit_mark3_record),
                ("submit audit mark=3 ringbuf_mem", submitted_ringbuf_record_with_mark3_any_path),
                ("write mark=7/11 field into submitted ringbuf_mem", submitted_ringbuf_record_with_mark7_or_11),
            ],
        )
    )
