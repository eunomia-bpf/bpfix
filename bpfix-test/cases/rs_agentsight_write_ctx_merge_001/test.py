#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import lookup_pinned_map
from bpf_case import lookup_pinned_map_value
from bpf_case import run_case


EVENT_TYPE_WRITE = 15
DETAIL_LEN = 8


def packet(pid: int, tid: int, ret: int, guarded: int, decoy_fd: int) -> bytes:
    return bytes([pid, tid, ret, guarded, decoy_fd]) + (b"\x00" * 59)


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def s32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def write_ctx_key(pid: int, tid: int) -> bytes:
    return u64((pid << 32) | tid)


def detail_for_fd(fd: int) -> bytes:
    raw = f"fd={fd % 10}".encode("ascii")
    return raw + (b"\x00" * (DETAIL_LEN - len(raw)))


def agg_key(pid: int, fd: int) -> bytes:
    return u32(pid) + u32(EVENT_TYPE_WRITE) + detail_for_fd(fd)


def agg_value(count: int, total_bytes: int, last_fd: int) -> bytes:
    return u64(count) + u64(total_bytes) + s32(last_fd) + u32(0)


def write_ctx_deleted(pid: int, tid: int):
    def check(map_dir: Path) -> bool:
        result = lookup_pinned_map(map_dir, "write_ctx_map", write_ctx_key(pid, tid))
        return result.returncode != 0

    return check


def write_ctx_still_present(pid: int, tid: int, fd: int):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "write_ctx_map", write_ctx_key(pid, tid))
        return value == s32(fd)

    return check


def agg_matches(pid: int, fd: int, expected: bytes):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "event_agg_map", agg_key(pid, fd))
        return value == expected

    return check


def agg_absent(pid: int, fd: int):
    def check(map_dir: Path) -> bool:
        result = lookup_pinned_map(map_dir, "event_agg_map", agg_key(pid, fd))
        return result.returncode != 0

    return check


def annotated_trace(load_output: str) -> str:
    marker = load_output.find("0: R1=ctx()")
    return load_output[marker:] if marker != -1 else load_output


def write_ctx_fd_loaded_before_delete(load_output: str) -> bool:
    trace = annotated_trace(load_output)
    lookup = trace.find("map=write_ctx_map,ks=8,vs=4")
    delete = trace.find("call bpf_map_delete_elem#3")
    if lookup == -1 or delete == -1 or lookup >= delete:
        return False
    before_delete = trace[lookup:delete]
    return re.search(r"=\s*\*\(u32 \*\)\(r\d+ \+0\)", before_delete) is not None


def delete_precedes_aggregate_update(load_output: str) -> bool:
    trace = annotated_trace(load_output)
    write_lookup = trace.find("map=write_ctx_map,ks=8,vs=4")
    delete = trace.find("call bpf_map_delete_elem#3")
    agg_lookup = trace.find("map=event_agg_map,ks=16,vs=24")
    agg_update = trace.find("call bpf_map_update_elem#2")
    return (
        write_lookup != -1
        and delete != -1
        and (agg_lookup != -1 or agg_update != -1)
        and write_lookup < delete
        and (delete < agg_lookup if agg_lookup != -1 else delete < agg_update)
    )


def aggregate_value_is_updated(load_output: str) -> bool:
    trace = annotated_trace(load_output)
    agg_lookup = trace.find("map=event_agg_map,ks=16,vs=24")
    if agg_lookup == -1:
        return "call bpf_map_update_elem#2" in trace
    region = trace[agg_lookup:]
    return (
        re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+0\)", region) is not None
        and re.search(r"\*\(u64 \*\)\(r\d+ \+0\) = r\d+", region) is not None
        and re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+8\)", region) is not None
        and re.search(r"\*\(u64 \*\)\(r\d+ \+8\) = r\d+", region) is not None
        and re.search(r"\*\(u32 \*\)\(r\d+ \+16\) = r\d+", region) is not None
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
                    "unguarded_exit_uses_saved_fd",
                    lambda: packet(7, 11, 12, 0, 8),
                    1,
                    [("write_ctx_map", write_ctx_key(7, 11), s32(3))],
                    [
                        ("pending write context is deleted", write_ctx_deleted(7, 11)),
                        ("aggregate key uses saved fd not packet decoy", agg_matches(7, 3, agg_value(1, 12, 3))),
                        ("decoy fd aggregate is absent", agg_absent(7, 8)),
                    ],
                ),
                (
                    "guarded_exit_updates_existing_aggregate",
                    lambda: packet(8, 12, 7, 1, 9),
                    1,
                    [
                        ("write_ctx_map", write_ctx_key(8, 12), s32(5)),
                        ("event_agg_map", agg_key(8, 5), agg_value(2, 20, 5)),
                    ],
                    [
                        ("guarded pending write context is deleted", write_ctx_deleted(8, 12)),
                        ("existing aggregate is incremented", agg_matches(8, 5, agg_value(3, 27, 5))),
                        ("guarded decoy fd aggregate is absent", agg_absent(8, 9)),
                    ],
                ),
                (
                    "missing_context_passes",
                    lambda: packet(9, 13, 10, 1, 6),
                    2,
                    [],
                    [("missing context does not aggregate decoy fd", agg_absent(9, 6))],
                ),
                (
                    "zero_return_keeps_pending_context",
                    lambda: packet(10, 14, 0, 0, 7),
                    2,
                    [("write_ctx_map", write_ctx_key(10, 14), s32(4))],
                    [("zero return leaves pending context untouched", write_ctx_still_present(10, 14, 4))],
                ),
            ],
            required_success_substrings=[
                "map=write_ctx_map,ks=8,vs=4",
                "call bpf_map_delete_elem#3",
                "map=event_agg_map,ks=16,vs=24",
            ],
            required_success_predicates=[
                ("saved write fd is loaded before delete", write_ctx_fd_loaded_before_delete),
                ("pending context delete precedes aggregate update", delete_precedes_aggregate_update),
                ("aggregate value is updated in place", aggregate_value_is_updated),
            ],
        )
    )
