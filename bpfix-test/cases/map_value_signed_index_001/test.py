#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def frame(index_byte: int) -> bytes:
    dest = bytes([0, 0x11, 0x22, 0x33, 0x44, index_byte & 0xFF])
    return dest + bytes.fromhex("66778899aabb0800") + (b"\x00" * 64)


def truncated_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def preserves_slot_normalization(source: Path) -> bool:
    text = strip_comments(source.read_text(encoding="utf-8"))
    slot_decl = re.search(r"\b__u32\s+slot\s*;", text)
    slot_assign = re.search(r"\bslot\s*=\s*\(\s*__u32\s*\)\s*\(\s*idx\s*\+\s*1\s*\)\s*;", text)
    slot_use = re.search(r"\bcfg->slots\s*\[\s*slot\s*\]", text)
    lookup = text.find("bpf_map_lookup_elem(&configs")
    return (
        slot_decl is not None
        and slot_assign is not None
        and slot_use is not None
        and lookup != -1
        and slot_assign.start() < lookup
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "unbounded min value",
            ],
            functional_tests=[
                ("negative_bucket_drops", lambda: frame(0xFF), 1),
                ("zero_bucket_passes", lambda: frame(0), 2),
                ("positive_bucket_drops", lambda: frame(1), 1),
                ("out_of_range_negative_passes", lambda: frame(0xFE), 2),
                ("out_of_range_positive_passes", lambda: frame(2), 2),
                ("truncated_passes", truncated_packet, 2),
            ],
            required_success_substrings=[
                "call bpf_map_lookup_elem#1",
            ],
            map_updates=[
                ("configs", struct.pack("<I", 0), struct.pack("<III", 1, 0, 1)),
            ],
            source_success_predicates=[
                ("case source invariant A", preserves_slot_normalization),
            ],
        )
    )
