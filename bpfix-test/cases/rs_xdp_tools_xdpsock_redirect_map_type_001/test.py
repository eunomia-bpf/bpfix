#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def packet(first_byte: int) -> bytes:
    return bytes([first_byte & 0xFF]) + (b"\x00" * 13)


def redirect_helper_uses_xskmap_after_rr_update(load_output: str) -> bool:
    in_annotated_trace = False
    window: list[str] = []
    current_r2_is_rr_slot = False
    current_r3_is_drop_fallback = False
    saw_rr_bss_update = False

    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
            window = []
            current_r2_is_rr_slot = False
            current_r3_is_drop_fallback = False
        if not in_annotated_trace:
            continue

        window.append(line)
        window = window[-12:]
        if re.search(r"\br2\s*(?:=|\+=|-=|&=|\|=|\^=|<<=|>>=)", line):
            current_r2_is_rr_slot = bool(
                re.search(r"\br2 &= 3\b", line)
                and ("umax32=3" in line or "var_off=(0x0; 0x3)" in line)
            )
        if re.search(r"\br3\s*(?:=|\+=|-=|&=|\|=|\^=|<<=|>>=)", line):
            current_r3_is_drop_fallback = re.search(r"\br3 = 1\b", line) is not None
        if re.search(r"map_value\(map=[^,\s]*\.bss", line) and re.search(
            r"\*\(u32 \*\)\(r1 \+0\) = r2", line
        ):
            saw_rr_bss_update = current_r2_is_rr_slot

        if "call bpf_redirect_map#51" not in line:
            continue
        recent = "\n".join(window)
        return (
            saw_rr_bss_update
            and "map_ptr(map=xsks_map" in recent
            and current_r2_is_rr_slot
            and current_r3_is_drop_fallback
        )
    return False


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "cannot pass map_type 2 into func bpf_redirect_map#51",
            ],
            functional_tests=[
                ("redirect_path_falls_back_to_drop", lambda: packet(0x01), 1),
                ("sentinel_byte_skips_redirect", lambda: packet(0xff), 2),
            ],
            required_success_substrings=[
                "call bpf_redirect_map#51",
                "map=xsks_map",
            ],
            required_success_predicates=[
                (
                    "redirect helper uses XSKMAP after round-robin state update",
                    redirect_helper_uses_xskmap_after_rr_update,
                ),
            ],
        )
    )
