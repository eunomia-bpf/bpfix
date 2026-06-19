#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def packet(tenant: int, selector: int) -> bytes:
    return bytes([tenant, selector]) + (b"\x00" * 62)


def key64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def cgroup_key(tenant: int, selector: int) -> bytes:
    return key64((tenant << 32) | selector)


def tracked_value(value: int) -> bytes:
    return bytes([value])


def tracked_cgroups_lookup_uses_u64_key(load_output: str) -> bool:
    helper = load_output.find("call bpf_map_lookup_elem#1")
    if helper == -1:
        return False
    before_helper = load_output[:helper]
    return (
        "map=tracked_cgroups,ks=8,vs=1" in load_output
        and re.search(r"\*\(u64 \*\)\(r10 -\d+\) = r\d+", before_helper) is not None
    )


def tracked_value_controls_drop(load_output: str) -> bool:
    lookup = load_output.find("map=tracked_cgroups,ks=8,vs=1")
    if lookup == -1:
        return False
    region = load_output[lookup:]
    return (
        re.search(r"=\s*\*\(u8 \*\)\(r\d+ \+0\)", region) is not None
        and "goto pc" in region
        and re.search(r"\br0 = 1\b", region) is not None
        and re.search(r"\br0 = 2\b", region) is not None
    )


def global_aggregate_is_updated(load_output: str) -> bool:
    lookup = load_output.find("map=prog.bss")
    if lookup == -1:
        return False
    region = load_output[lookup:]
    return (
        re.search(r"\*\(u64 \*\)\(r\d+ \+0\) = r\d+", region) is not None
        and (
            re.search(r"\*\(u32 \*\)\(r\d+ \+8\) = r\d+", region) is not None
            or (
                "map=prog.bss,ks=4,vs=12,off=8" in region
                and re.search(r"\*\(u32 \*\)\(r\d+ \+0\) = r\d+", region) is not None
            )
        )
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid read from stack",
                "size=8",
            ],
            functional_tests=[
                (
                    "tracked_child_drops",
                    lambda: packet(3, 7),
                    1,
                    [("tracked_cgroups", cgroup_key(3, 7), tracked_value(1))],
                ),
                (
                    "tracked_zero_value_passes",
                    lambda: packet(3, 8),
                    2,
                    [("tracked_cgroups", cgroup_key(3, 8), tracked_value(0))],
                ),
                (
                    "same_child_different_tenant_passes",
                    lambda: packet(4, 7),
                    2,
                    [("tracked_cgroups", cgroup_key(3, 7), tracked_value(1))],
                ),
                ("direct_target_drops_without_map", lambda: packet(0x42, 7), 1),
                ("untracked_child_passes", lambda: packet(3, 9), 2),
                ("zero_selector_passes", lambda: packet(3, 0), 2),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
                "map=tracked_cgroups,ks=8,vs=1",
                "map=prog.bss",
            ],
            required_success_predicates=[
                ("tracked_cgroups lookup uses an initialized 64-bit key", tracked_cgroups_lookup_uses_u64_key),
                ("tracked map value controls drop/pass decision", tracked_value_controls_drop),
                ("tracked child path updates aggregate state", global_aggregate_is_updated),
            ],
        )
    )
