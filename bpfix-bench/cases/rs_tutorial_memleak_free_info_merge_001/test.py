#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import lookup_pinned_map
from bpf_case import lookup_pinned_map_value
from bpf_case import run_case


def packet(selector: int, guarded: int) -> bytes:
    return bytes([selector, guarded]) + (b"\x00" * 62)


def key64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def alloc_info(size: int, stack_id: int) -> bytes:
    return size.to_bytes(8, "little") + (1234).to_bytes(8, "little") + stack_id.to_bytes(8, "little")


def combined_info(total_size: int, count: int) -> bytes:
    return total_size.to_bytes(8, "little") + count.to_bytes(8, "little")


def alloc_entry_deleted(map_dir: Path) -> bool:
    result = lookup_pinned_map(map_dir, "allocs", key64(7))
    return result.returncode != 0


def combined_stats_decremented(map_dir: Path) -> bool:
    value, _ = lookup_pinned_map_value(map_dir, "combined_allocs", key64(3))
    return value == combined_info(192, 3)


def annotated_trace(load_output: str) -> str:
    marker = load_output.find("0: R1=ctx()")
    return load_output[marker:] if marker != -1 else load_output


def alloc_info_fields_loaded_before_delete(load_output: str) -> bool:
    trace = annotated_trace(load_output)
    delete = trace.find("call bpf_map_delete_elem#3")
    if delete == -1:
        return False
    before_delete = trace[:delete]
    return (
        "map=allocs,ks=8,vs=24" in before_delete
        and re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+0\)", before_delete) is not None
        and re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+16\)", before_delete) is not None
    )


def alloc_delete_precedes_combined_update(load_output: str) -> bool:
    trace = annotated_trace(load_output)
    alloc_lookup = trace.find("map=allocs,ks=8,vs=24")
    delete = trace.find("call bpf_map_delete_elem#3")
    combined_lookup = trace.find("map=combined_allocs,ks=8,vs=16")
    return alloc_lookup != -1 and delete != -1 and combined_lookup != -1 and alloc_lookup < delete < combined_lookup


def combined_stats_are_decremented(load_output: str) -> bool:
    trace = annotated_trace(load_output)
    combined_lookup = trace.find("map=combined_allocs,ks=8,vs=16")
    if combined_lookup == -1:
        return False
    region = trace[combined_lookup:]
    return (
        re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+0\)", region) is not None
        and re.search(r"\br\d+ -= r\d+\b", region) is not None
        and re.search(r"\*\(u64 \*\)\(r\d+ \+0\) = r\d+", region) is not None
        and re.search(r"=\s*\*\(u64 \*\)\(r\d+ \+8\)", region) is not None
        and re.search(r"\*\(u64 \*\)\(r\d+ \+8\) = r\d+", region) is not None
    )


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def preserves_alloc_info_snapshot_shape(source: Path) -> bool:
    text = strip_comments(source.read_text(encoding="utf-8"))
    stack = re.search(r"\b__u64\s+stack_id\s*=\s*info->stack_id\s*;", text)
    size = re.search(r"\b__u64\s+sz\s*=\s*info->size\s*;", text)
    delete = text.find("bpf_map_delete_elem(&allocs")
    update = text.find("update_statistics_del(stack_id, sz)")
    return (
        stack is not None
        and size is not None
        and delete != -1
        and update != -1
        and stack.start() < delete < update
        and size.start() < delete
        and "guarded_path & 1" not in text[text.find("if (!info)") :]
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
                    "known_free_unguarded_drops",
                    lambda: packet(7, 0),
                    1,
                    [
                        ("allocs", key64(7), alloc_info(64, 3)),
                        ("combined_allocs", key64(3), combined_info(256, 4)),
                    ],
                    [
                        ("allocs entry is deleted after free", alloc_entry_deleted),
                        ("combined stats are decremented after free", combined_stats_decremented),
                    ],
                ),
                (
                    "known_free_guarded_drops",
                    lambda: packet(7, 1),
                    1,
                    [
                        ("allocs", key64(7), alloc_info(64, 3)),
                        ("combined_allocs", key64(3), combined_info(256, 4)),
                    ],
                    [
                        ("allocs entry is deleted after guarded free", alloc_entry_deleted),
                        ("combined stats are decremented after guarded free", combined_stats_decremented),
                    ],
                ),
                ("missing_free_passes", lambda: packet(9, 0), 2),
                ("zero_selector_missing_passes", lambda: packet(0, 0), 2),
            ],
            required_success_substrings=[
                "map=allocs,ks=8,vs=24",
                "call bpf_map_delete_elem#3",
                "map=combined_allocs,ks=8,vs=16",
            ],
            required_success_predicates=[
                ("allocation size and stack_id loaded before delete", alloc_info_fields_loaded_before_delete),
                ("alloc delete precedes combined stats update", alloc_delete_precedes_combined_update),
                ("combined allocation statistics are decremented", combined_stats_are_decremented),
            ],
            source_success_predicates=[
                ("case source invariant A", preserves_alloc_info_snapshot_shape),
            ],
        )
    )
