#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import lookup_pinned_map
from bpf_case import lookup_pinned_map_value
from bpf_case import run_case


RS_MMAP_BASE = 0x100000
PATH_LEN = 16


def packet(pid: int, tid: int, fd: int, guarded: int, start_slot: int) -> bytes:
    return bytes([pid, tid, fd, guarded, start_slot]) + (b"\x00" * 59)


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def s32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def pending_value(fd: int, length: int, prot: int, flags: int) -> bytes:
    return s32(fd) + u32(0) + u64(length) + u64(prot) + u64(flags)


def fd_key(pid: int, fd: int) -> bytes:
    return s32(pid) + s32(fd)


def mmap_key(pid: int, start: int) -> bytes:
    return s32(pid) + u32(0) + u64(start)


def padded_path(text: str) -> bytes:
    raw = text.encode("ascii")
    return raw + (b"\x00" * (PATH_LEN - len(raw)))


def fd_ref_value(path: str, ino: int, dev: int) -> bytes:
    return padded_path(path) + u64(ino) + u64(dev)


def mmap_ref_value(path: str, start: int, length: int, prot: int, flags: int, ino: int, dev: int) -> bytes:
    return padded_path(path) + u64(start) + u64(start + length) + u64(prot) + u64(flags) + u64(ino) + u64(dev)


def index_value(start: int) -> bytes:
    return u64(start) + (b"\x00" * 24) + u32(1) + u32(0)


def pending_deleted(tid: int):
    def check(map_dir: Path) -> bool:
        result = lookup_pinned_map(map_dir, "ts_mmappend", u64(tid))
        return result.returncode != 0

    return check


def mmap_ref_matches(pid: int, start: int, expected: bytes):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "ts_mmap", mmap_key(pid, start))
        return value == expected

    return check


def index_matches(pid: int, start: int):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "ts_mmap_index", s32(pid))
        return value == index_value(start)

    return check


def annotated_trace(load_output: str) -> str:
    marker = load_output.find("0: R1=ctx()")
    return load_output[marker:] if marker != -1 else load_output


def mmap_workflow_is_preserved(load_output: str) -> bool:
    trace = annotated_trace(load_output)
    pending = trace.find("map=ts_mmappend,ks=8,vs=32")
    fd_lookup = trace.find("map=ts_fd,ks=8,vs=32")
    index_update = trace.find("map=ts_mmap_index")
    mmap_update = trace.find("map=ts_mmap,ks=16,vs=64")
    pending_delete = trace.find("call bpf_map_delete_elem#3")
    return (
        pending != -1
        and fd_lookup != -1
        and index_update != -1
        and mmap_update != -1
        and pending_delete != -1
        and pending < fd_lookup < mmap_update < pending_delete
    )


def mmap_ref_uses_fd_path_and_pending_fields(load_output: str) -> bool:
    trace = annotated_trace(load_output)
    mmap_update = trace.find("map=ts_mmap,ks=16,vs=64")
    if mmap_update == -1:
        return False
    before_update = trace[:mmap_update]
    return (
        "map=ts_fd,ks=8,vs=32" in before_update
        and re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+8\)", before_update) is not None
        and re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+16\)", before_update) is not None
        and re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+24\)", before_update) is not None
    )


def fd_lookup_uses_pending_fd(load_output: str) -> bool:
    trace = annotated_trace(load_output)
    pending_lookup = trace.find("map=ts_mmappend,ks=8,vs=32")
    fd_lookup = trace.find("map=ts_fd,ks=8,vs=32")
    if pending_lookup == -1 or fd_lookup == -1 or pending_lookup >= fd_lookup:
        return False
    between = trace[pending_lookup:fd_lookup]
    return re.search(r"=\s*\*\(u32 \*\)\(r\d+ \+0\)", between) is not None


if __name__ == "__main__":
    start_a = RS_MMAP_BASE + (3 << 12)
    start_b = RS_MMAP_BASE + (5 << 12)
    mmap_a = mmap_ref_value("alpha.so", start_a, 64, 1, 2, 0xABC, 0x11)
    mmap_b = mmap_ref_value("beta.bin", start_b, 128, 3, 4, 0xDEF, 0x22)

    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid mem access 'map_value_or_null'",
            ],
            functional_tests=[
                (
                    "mmap_exit_fd3_unguarded_updates_state",
                    lambda: packet(7, 11, 99, 0, 3),
                    1,
                    [
                        ("ts_mmappend", u64(11), pending_value(3, 64, 1, 2)),
                        ("ts_fd", fd_key(7, 3), fd_ref_value("alpha.so", 0xABC, 0x11)),
                    ],
                    [
                        ("pending mmap entry deleted", pending_deleted(11)),
                        ("mmap ref stores fd path and pending fields", mmap_ref_matches(7, start_a, mmap_a)),
                        ("mmap index remembers start", index_matches(7, start_a)),
                    ],
                ),
                (
                    "mmap_exit_fd4_guarded_updates_state",
                    lambda: packet(8, 12, 98, 1, 5),
                    1,
                    [
                        ("ts_mmappend", u64(12), pending_value(4, 128, 3, 4)),
                        ("ts_fd", fd_key(8, 4), fd_ref_value("beta.bin", 0xDEF, 0x22)),
                    ],
                    [
                        ("guarded pending mmap entry deleted", pending_deleted(12)),
                        ("guarded mmap ref stores fd path and pending fields", mmap_ref_matches(8, start_b, mmap_b)),
                        ("guarded mmap index remembers start", index_matches(8, start_b)),
                    ],
                ),
                (
                    "missing_pending_passes",
                    lambda: packet(7, 13, 3, 0, 3),
                    2,
                    [("ts_fd", fd_key(7, 3), fd_ref_value("alpha.so", 0xABC, 0x11))],
                ),
                (
                    "missing_fd_deletes_pending_and_passes",
                    lambda: packet(7, 14, 9, 1, 3),
                    2,
                    [("ts_mmappend", u64(14), pending_value(9, 64, 1, 2))],
                    [("pending deleted even when fd is missing", pending_deleted(14))],
                ),
            ],
            required_success_substrings=[
                "map=ts_mmappend,ks=8,vs=32",
                "map=ts_fd,ks=8,vs=32",
                "map=ts_mmap,ks=16,vs=64",
                "map=ts_mmap_index",
            ],
            required_success_predicates=[
                ("pending-fd-mmap-delete workflow is preserved", mmap_workflow_is_preserved),
                ("fd lookup uses pending mmap fd", fd_lookup_uses_pending_fd),
                ("mmap ref uses fd path and pending fields", mmap_ref_uses_fd_path_and_pending_fields),
            ],
        )
    )
