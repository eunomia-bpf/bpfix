#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import lookup_pinned_map
from bpf_case import lookup_pinned_map_value
from bpf_case import run_case
from bpf_case import submitted_ringbuf_refs


XDP_DROP = 1
XDP_PASS = 2


def packet(prev_pid: int, next_pid: int, now_ns: int, require_known_ts: int, emit_event: int = 1) -> bytes:
    return (
        u32(prev_pid)
        + u32(next_pid)
        + u64(now_ns)
        + u32(require_known_ts)
        + u32(emit_event)
    )


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def stats_value(
    *,
    processed: int,
    passed: int,
    prev_pid: int,
    next_pid: int,
    delta: int,
    runtime: int,
    event_pid: int,
    next_ts: int,
) -> bytes:
    return b"".join(
        [
            u64(processed),
            u64(passed),
            u64(prev_pid),
            u64(next_pid),
            u64(delta),
            u64(runtime),
            u64(event_pid),
            u64(next_ts),
        ]
    )


def zero_stats() -> bytes:
    return stats_value(
        processed=0,
        passed=0,
        prev_pid=0,
        next_pid=0,
        delta=0,
        runtime=0,
        event_pid=0,
        next_ts=0,
    )


def time_value(pid: int, expected: int):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "time_lookup", u32(pid))
        return value == u64(expected)

    return check


def runtime_value(pid: int, expected: int):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "runtime_lookup", u32(pid))
        return value == u64(expected)

    return check


def runtime_absent(pid: int):
    def check(map_dir: Path) -> bool:
        result = lookup_pinned_map(map_dir, "runtime_lookup", u32(pid))
        return result.returncode != 0

    return check


def stats_matches(expected: bytes):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "stats", u32(0))
        return value == expected

    return check


def trace_region(load_output: str) -> str:
    marker = load_output.find("0: R1=ctx()")
    return load_output[marker:] if marker != -1 else load_output


def time_lookup_dereferenced_before_runtime_update(load_output: str) -> bool:
    trace = trace_region(load_output)
    lookup = trace.find("map=time_lookup,ks=4,vs=8")
    runtime_lookup = trace.find("map=runtime_lookup,ks=4,vs=8")
    if lookup == -1 or runtime_lookup == -1 or lookup > runtime_lookup:
        return False
    region = trace[lookup:runtime_lookup]
    return re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+0\)", region) is not None


def runtime_update_precedes_ringbuf_submit(load_output: str) -> bool:
    trace = trace_region(load_output)
    runtime_lookup = trace.find("map=runtime_lookup,ks=4,vs=8")
    submit = trace.find("call bpf_ringbuf_submit#132")
    if runtime_lookup == -1 or submit == -1:
        return False
    update = trace.find("call bpf_map_update_elem#2", runtime_lookup)
    return update != -1 and update < submit


def ringbuf_record_is_submitted(load_output: str) -> bool:
    return bool(submitted_ringbuf_refs(load_output, expected_ringbuf_size=24))


def time_lookup_updated_after_runtime_path(load_output: str) -> bool:
    trace = trace_region(load_output)
    runtime = trace.find("map=runtime_lookup,ks=4,vs=8")
    if runtime == -1:
        return False
    later = trace[runtime:]
    return later.count("call bpf_map_update_elem#2") >= 2


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'map_value_or_null'",
            ],
            functional_tests=[
                (
                    "existing_runtime_accumulates_and_emits",
                    lambda: packet(7, 11, 9000, 1, 1),
                    XDP_DROP,
                    [
                        ("stats", u32(0), zero_stats()),
                        ("time_lookup", u32(7), u64(1000)),
                        ("runtime_lookup", u32(7), u64(3)),
                    ],
                    [
                        ("runtime map accumulates delta", runtime_value(7, 8003)),
                        ("next process timestamp is stored", time_value(11, 9000)),
                        (
                            "stats record processed runtime",
                            stats_matches(
                                stats_value(
                                    processed=1,
                                    passed=0,
                                    prev_pid=7,
                                    next_pid=11,
                                    delta=8000,
                                    runtime=8003,
                                    event_pid=7,
                                    next_ts=9000,
                                )
                            ),
                        ),
                    ],
                ),
                (
                    "new_runtime_created",
                    lambda: packet(5, 6, 7000, 1, 1),
                    XDP_DROP,
                    [
                        ("stats", u32(0), zero_stats()),
                        ("time_lookup", u32(5), u64(2000)),
                    ],
                    [
                        ("runtime map creates new total", runtime_value(5, 5000)),
                        ("next process timestamp is stored", time_value(6, 7000)),
                        (
                            "stats record created runtime",
                            stats_matches(
                                stats_value(
                                    processed=1,
                                    passed=0,
                                    prev_pid=5,
                                    next_pid=6,
                                    delta=5000,
                                    runtime=5000,
                                    event_pid=5,
                                    next_ts=7000,
                                )
                            ),
                        ),
                    ],
                ),
                (
                    "missing_timestamp_passes_with_guard",
                    lambda: packet(9, 10, 4000, 1, 1),
                    XDP_PASS,
                    [("stats", u32(0), zero_stats())],
                    [
                        ("missing previous runtime is not created", runtime_absent(9)),
                        ("next process timestamp is still recorded", time_value(10, 4000)),
                        (
                            "stats record guarded pass",
                            stats_matches(
                                stats_value(
                                    processed=0,
                                    passed=1,
                                    prev_pid=9,
                                    next_pid=10,
                                    delta=0,
                                    runtime=0,
                                    event_pid=0,
                                    next_ts=4000,
                                )
                            ),
                        ),
                    ],
                ),
                (
                    "unguarded_existing_timestamp_still_processes",
                    lambda: packet(3, 4, 14000, 0, 1),
                    XDP_DROP,
                    [
                        ("stats", u32(0), zero_stats()),
                        ("time_lookup", u32(3), u64(11000)),
                    ],
                    [
                        ("unguarded existing timestamp still updates runtime", runtime_value(3, 3000)),
                        ("unguarded path records next timestamp", time_value(4, 14000)),
                        (
                            "stats record unguarded runtime",
                            stats_matches(
                                stats_value(
                                    processed=1,
                                    passed=0,
                                    prev_pid=3,
                                    next_pid=4,
                                    delta=3000,
                                    runtime=3000,
                                    event_pid=3,
                                    next_ts=14000,
                                )
                            ),
                        ),
                    ],
                ),
                (
                    "stale_timestamp_passes_without_runtime_update",
                    lambda: packet(12, 13, 1000, 1, 1),
                    XDP_PASS,
                    [
                        ("stats", u32(0), zero_stats()),
                        ("time_lookup", u32(12), u64(9000)),
                    ],
                    [
                        ("stale timestamp does not create runtime", runtime_absent(12)),
                        ("stale timestamp still records next process start", time_value(13, 1000)),
                        (
                            "stats record stale pass",
                            stats_matches(
                                stats_value(
                                    processed=0,
                                    passed=1,
                                    prev_pid=12,
                                    next_pid=13,
                                    delta=0,
                                    runtime=0,
                                    event_pid=0,
                                    next_ts=1000,
                                )
                            ),
                        ),
                    ],
                ),
            ],
            required_success_substrings=[
                "map=time_lookup,ks=4,vs=8",
                "map=runtime_lookup,ks=4,vs=8",
                "call bpf_map_update_elem#2",
                "call bpf_ringbuf_reserve#131",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("time_lookup value is dereferenced before runtime update", time_lookup_dereferenced_before_runtime_update),
                ("runtime total is persisted before ringbuf submit", runtime_update_precedes_ringbuf_submit),
                ("ringbuf runtime record is submitted", ringbuf_record_is_submitted),
                ("time_lookup next timestamp update remains after runtime path", time_lookup_updated_after_runtime_path),
            ],
        )
    )
