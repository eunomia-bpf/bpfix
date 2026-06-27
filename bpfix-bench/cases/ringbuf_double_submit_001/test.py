#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import (
    parse_args,
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


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def audit_reserve_failure_drops(text: str) -> bool:
    text = strip_comments(text)
    reserve = re.search(r"\baudit\s*=\s*bpf_ringbuf_reserve\s*\([^;]+;", text)
    if reserve is None:
        return False
    after_reserve = text[reserve.end() :]
    check = re.search(r"\bif\s*\(\s*!\s*audit\s*\)\s*(?:\{(?P<braced>.*?)\}|(?P<stmt>[^;]+;))", after_reserve, re.DOTALL)
    if check is None:
        return False
    body = check.group("braced") if check.group("braced") is not None else check.group("stmt")
    return re.search(r"\breturn\s+XDP_DROP\s*;", body) is not None


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = source.read_text(encoding="utf-8")
    return [{"name": "audit reserve failure keeps IPv4 drop semantics", "passed": audit_reserve_failure_drops(text)}]


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    if not args.expect_reject:
        checks = source_semantics(args.source)
        if not all(check["passed"] for check in checks):
            print(
                json.dumps(
                    {
                        "source": str(args.source.resolve()),
                        "expect_reject": args.expect_reject,
                        "source_semantics": checks,
                        "passed": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            raise SystemExit(1)

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
