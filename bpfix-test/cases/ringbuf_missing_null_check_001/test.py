#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import (
    ringbuf_refs_written_with_u32_value,
    run_case,
    submitted_ringbuf_record_with_mark3_any_path,
    submitted_ringbuf_record_with_mark7,
    submitted_ringbuf_record_with_mark11,
    submitted_ringbuf_refs,
)


def ethernet_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 64)


def arp_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0806") + (b"\x00" * 64)


def truncated_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb08")


def discarded_audit_mark3_record(log: str) -> bool:
    return bool(
        ringbuf_refs_written_with_u32_value(log, 3)
        & submitted_ringbuf_refs(log, helper_call="call bpf_ringbuf_discard#133")
    )


def submitted_ringbuf_record_with_mark13(log: str) -> bool:
    return bool(ringbuf_refs_written_with_u32_value(log, 13) & submitted_ringbuf_refs(log))


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def rec_cleanup_precedes_audit_cleanup(source: Path) -> bool:
    text = strip_comments(source.read_text(encoding="utf-8"))
    truncation = re.search(
        r"\bif\s*\(\s*data\s*\+\s*14\s*>\s*data_end\s*\)\s*\{(?P<body>.*?)\}",
        text,
        flags=re.DOTALL,
    )
    if truncation is None:
        return False
    body = truncation.group("body")
    rec_first = body.find("bpf_ringbuf_discard(rec, 0)")
    audit_after = body.find("bpf_ringbuf_discard(audit, 0)", rec_first)
    return rec_first != -1 and audit_after != -1


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "R7 invalid mem access 'ringbuf_mem_or_null'",
            ],
            functional_tests=[
                ("ipv4_xdp_pass", ethernet_frame, 2),
                ("arp_xdp_pass", arp_frame, 2),
                ("truncated_xdp_pass", truncated_frame, 2),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "R0_w=ringbuf_mem_or_null",
                "call bpf_ringbuf_discard#133",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("discard audit mark=3 ringbuf_mem on rec allocation failure", discarded_audit_mark3_record),
                ("submit audit mark=3 ringbuf_mem", submitted_ringbuf_record_with_mark3_any_path),
                ("write mark=7 into submitted ringbuf_mem", submitted_ringbuf_record_with_mark7),
                ("write mark=11 into submitted ringbuf_mem", submitted_ringbuf_record_with_mark11),
                ("write mark=13 into submitted ringbuf_mem", submitted_ringbuf_record_with_mark13),
            ],
            source_success_predicates=[
                ("case source invariant A", rec_cleanup_precedes_audit_cleanup),
            ],
        )
    )
