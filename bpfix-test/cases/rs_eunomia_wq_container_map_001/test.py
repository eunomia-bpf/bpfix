#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import lookup_pinned_map_value
from bpf_case import run_case


XDP_DROP = 1
XDP_PASS = 2


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def request(key: int, value: int, schedule: int) -> bytes:
    return u32(key) + u32(value) + u32(schedule) + (b"\0" * 16)


def zero_stats() -> bytes:
    return b"\0" * 40


def stats_value(*, processed: int, skipped: int, scheduled: int, last_key: int, last_value: int) -> bytes:
    return b"".join(
        [
            u64(processed),
            u64(skipped),
            u64(scheduled),
            u64(last_key),
            u64(last_value),
        ]
    )


def stats_matches(expected: bytes):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "stats_map", u32(0))
        return value == expected

    return check


def work_item_value(key: int, expected_value: int, expected_scheduled_low: int):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "work_items", u32(key))
        if len(value) < 8:
            return False
        actual_value = int.from_bytes(value[0:4], "little")
        actual_scheduled = int.from_bytes(value[4:8], "little")
        return actual_value >= expected_value and actual_scheduled >= expected_scheduled_low

    return check


def workqueue_lifecycle_is_ordered(load_output: str) -> bool:
    init = load_output.find("call bpf_wq_init")
    callback = load_output.find("call bpf_wq_set_callback_impl")
    start = load_output.find("call bpf_wq_start")
    return init != -1 and callback != -1 and start != -1 and init < callback < start


def workqueue_state_recorded_before_start(load_output: str) -> bool:
    start = load_output.find("call bpf_wq_start")
    if start == -1:
        return False
    before = load_output[:start]
    return re.search(r"\*\(u32 \*\)\(r\d+ \+0\) = r\d+", before) is not None and re.search(
        r"\*\(u32 \*\)\(r\d+ \+4\) = (?:1|r\d+)", before
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "bpf_wq_init",
            ],
            functional_tests=[
                (
                    "malformed_packet_passes",
                    lambda: b"\0" * 8,
                    XDP_PASS,
                    [("stats_map", u32(0), zero_stats())],
                    [("stats unchanged on malformed packet", stats_matches(zero_stats()))],
                ),
                (
                    "schedule_disabled_passes_with_accounting",
                    lambda: request(2, 55, 0),
                    XDP_PASS,
                    [("stats_map", u32(0), zero_stats())],
                    [
                        (
                            "disabled schedule increments skipped",
                            stats_matches(
                                stats_value(
                                    processed=1,
                                    skipped=1,
                                    scheduled=0,
                                    last_key=0,
                                    last_value=0,
                                )
                            ),
                        )
                    ],
                ),
                (
                    "schedule_records_work_item_and_drops",
                    lambda: request(6, 77, 1),
                    XDP_DROP,
                    [("stats_map", u32(0), zero_stats())],
                    [
                        (
                            "schedule path updates stats",
                            stats_matches(
                                stats_value(
                                    processed=1,
                                    skipped=0,
                                    scheduled=1,
                                    last_key=2,
                                    last_value=77,
                                )
                            ),
                        ),
                        ("work item is initialized before start", work_item_value(2, 77, 1)),
                    ],
                ),
            ],
            required_success_substrings=[
                "map=work_items,ks=4,vs=24",
                "call bpf_wq_init",
                "call bpf_wq_set_callback_impl",
                "call bpf_wq_start",
            ],
            required_success_predicates=[
                ("workqueue callback is registered before start", workqueue_lifecycle_is_ordered),
                ("work item state is recorded before start", workqueue_state_recorded_before_start),
            ],
        )
    )
