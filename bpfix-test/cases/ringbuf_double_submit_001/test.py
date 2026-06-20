#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import (
    ringbuf_refs_for_register,
    ringbuf_refs_written_with_u32_value,
    run_case,
    submitted_ringbuf_refs,
)


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def truncated_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb")


def submitted_primary_mark7_record(log: str) -> bool:
    written = ringbuf_refs_written_with_u32_value(log, 7, expected_ringbuf_size=8)
    return bool(written & submitted_ringbuf_refs(log, expected_ringbuf_size=8))


def submitted_audit_mark99_record(log: str) -> bool:
    written = ringbuf_refs_written_with_u32_value(log, 99, expected_ringbuf_size=8)
    return bool(written & submitted_ringbuf_refs(log, expected_ringbuf_size=8))


def submitted_audit_record_with_ipv4_proto(log: str) -> bool:
    audit_refs = ringbuf_refs_written_with_u32_value(log, 99, expected_ringbuf_size=8)
    proto_refs: set[str] = set()
    in_trace = False
    for line in log.splitlines():
        if line.startswith("0: R1="):
            in_trace = True
        if not in_trace:
            continue
        store = re.search(r"\*\(u32 \*\)\(r(\d+)\s*\+\s*4\)\s*=\s*r\d+", line)
        if store is not None:
            proto_refs.update(ringbuf_refs_for_register(line, store.group(1), expected_size=8))
    return bool(audit_refs & proto_refs & submitted_ringbuf_refs(log, expected_ringbuf_size=8))


def submitted_two_distinct_8byte_records(log: str) -> bool:
    return len(submitted_ringbuf_refs(log, expected_ringbuf_size=8)) >= 2


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'scalar'",
            ],
            functional_tests=[
                ("ipv4_submits_primary_and_audit_then_drops", lambda: frame(0x0800), 1),
                ("arp_submits_primary_once_and_passes", lambda: frame(0x0806), 2),
                ("truncated_passes", truncated_packet, 2),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("submit primary mark=7 ringbuf record", submitted_primary_mark7_record),
                ("submit audit mark=99 ringbuf record", submitted_audit_mark99_record),
                ("submit audit record with ipv4 proto", submitted_audit_record_with_ipv4_proto),
                ("submit at least two distinct ringbuf records", submitted_two_distinct_8byte_records),
            ],
        )
    )
