#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import lookup_pinned_map
from bpf_case import lookup_pinned_map_value
from bpf_case import run_case


DETAIL_LEN = 8
EVENT_TYPE_FILE_DELETE = 15


def packet(pid: int, event_selector: int, guarded_overflow: int, path: str) -> bytes:
    raw_path = path.encode("ascii")[:31] + b"\x00"
    raw_path = raw_path + (b"\x00" * (32 - len(raw_path)))
    return bytes([pid & 0xFF, event_selector & 0xFF, guarded_overflow & 0xFF]) + raw_path + (b"\x00" * 29)


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def detail_for_path(path: str) -> bytes:
    raw = path.encode("ascii")[: DETAIL_LEN - 1]
    last_slash = 0
    out = bytearray(DETAIL_LEN)
    for idx, byte in enumerate(raw):
        if byte == 0:
            break
        if byte == ord("/"):
            last_slash = idx
        out[idx] = byte
    if last_slash > 0:
        out[last_slash] = 0
    return bytes(out)


def agg_key(pid: int, path: str) -> bytes:
    return u32(pid) + u32(EVENT_TYPE_FILE_DELETE) + detail_for_path(path)


def agg_value(count: int, marker: int, path: str) -> bytes:
    return u64(count) + u64(marker) + detail_for_path(path)


def overflow_key() -> bytes:
    return u32(0)


def agg_matches(pid: int, path: str, expected: bytes):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "event_agg_map", agg_key(pid, path))
        return value == expected

    return check


def agg_absent(pid: int, path: str):
    def check(map_dir: Path) -> bool:
        result = lookup_pinned_map(map_dir, "event_agg_map", agg_key(pid, path))
        return result.returncode != 0

    return check


def overflow_matches(expected: int):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "agg_overflow_count", overflow_key())
        return value == u64(expected)

    return check


def trace_region(load_output: str) -> str:
    marker = load_output.find("0: R1=ctx()")
    return load_output[marker:] if marker != -1 else load_output


def overflow_lookup_precedes_atomic_add(load_output: str) -> bool:
    trace = trace_region(load_output)
    lookup = trace.find("map=agg_overflow_co,ks=4,vs=8")
    if lookup == -1:
        return False
    region = trace[lookup:]
    atomic = re.search(r"(?:lock )?\*\(u64 \*\)\(r\d+ \+0\) \+=", region)
    return atomic is not None


def guarded_overflow_keeps_base_increment(load_output: str) -> bool:
    live_start = load_output.find("Live regs before insn:")
    if live_start == -1:
        return False
    annotated_start = load_output.find("0: R1=ctx()", live_start)
    if annotated_start == -1:
        return False
    trace = load_output[live_start:annotated_start]
    update = trace.find("call bpf_map_update_elem#2")
    if update == -1:
        return False

    overflow_lookups = [
        match.start()
        for match in re.finditer(r"call bpf_map_lookup_elem#1", trace)
        if match.start() > update
    ]
    if len(overflow_lookups) < 2:
        return False

    guarded_region = trace[overflow_lookups[1] :]
    atomic_adds = re.findall(r"(?:lock )?\*\(u64 \*\)\(r\d+ \+0\) \+=", guarded_region)
    return len(atomic_adds) >= 2


def event_update_failure_path_preserved(load_output: str) -> bool:
    trace = trace_region(load_output)
    update = trace.find("call bpf_map_update_elem#2")
    overflow = trace.find("map=agg_overflow_co,ks=4,vs=8")
    return update != -1 and overflow != -1 and update < overflow


def existing_aggregate_is_updated(load_output: str) -> bool:
    trace = trace_region(load_output)
    lookup = trace.find("map=event_agg_map,ks=16,vs=24")
    if lookup == -1:
        return False
    region = trace[lookup:]
    return (
        re.search(r"\*\(u64 \*\)\(r\d+ \+0\) \+= r\d+", region) is not None
        and re.search(r"\*\(u64 \*\)\(r\d+ \+8\) = r\d+", region) is not None
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'map_value_or_null'",
            ],
            functional_tests=[
                (
                    "existing_aggregate_updates_in_place",
                    lambda: packet(7, 1, 0, "/tmp/a"),
                    1,
                    [("event_agg_map", agg_key(7, "/tmp/a"), agg_value(2, 55, "/tmp/a"))],
                    [("existing aggregate count and marker update", agg_matches(7, "/tmp/a", agg_value(3, 7, "/tmp/a")))],
                ),
                (
                    "new_path_inserts_aggregate",
                    lambda: packet(8, 1, 1, "/var/log/app"),
                    1,
                    [("agg_overflow_count", overflow_key(), u64(4))],
                    [
                        ("new aggregate is inserted", agg_matches(8, "/var/log/app", agg_value(1, 8, "/var/log/app"))),
                        ("overflow counter is unchanged", overflow_matches(4)),
                    ],
                ),
                (
                    "full_aggregate_map_increments_overflow",
                    lambda: packet(9, 1, 1, "/new/file"),
                    1,
                    [
                        ("event_agg_map", agg_key(3, "/full/c"), agg_value(1, 3, "/full/c")),
                        ("event_agg_map", agg_key(4, "/full/d"), agg_value(1, 4, "/full/d")),
                        ("agg_overflow_count", overflow_key(), u64(7)),
                    ],
                    [
                        ("overflow counter is incremented", overflow_matches(8)),
                        ("overflowed key is not inserted", agg_absent(9, "/new/file")),
                    ],
                ),
                (
                    "disabled_selector_has_no_side_effect",
                    lambda: packet(10, 0, 1, "/off/file"),
                    2,
                    [("agg_overflow_count", overflow_key(), u64(11))],
                    [
                        ("disabled selector does not aggregate", agg_absent(10, "/off/file")),
                        ("disabled selector leaves overflow unchanged", overflow_matches(11)),
                    ],
                ),
            ],
            required_success_substrings=[
                "map=event_agg_map,ks=16,vs=24",
                "call bpf_map_update_elem#2",
                "map=agg_overflow_co,ks=4,vs=8",
            ],
            required_success_predicates=[
                ("event update failure path reaches overflow accounting", event_update_failure_path_preserved),
                ("overflow lookup is followed by the atomic increment", overflow_lookup_precedes_atomic_add),
                ("guarded overflow keeps base counter increment", guarded_overflow_keeps_base_increment),
                ("existing aggregate value is updated in place", existing_aggregate_is_updated),
            ],
        )
    )
