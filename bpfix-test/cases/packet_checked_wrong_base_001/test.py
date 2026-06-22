#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def fourteen_byte_ipv4_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def uses_typed_eth_header_for_proto(source: Path) -> bool:
    text = strip_comments(source.read_text(encoding="utf-8"))
    return (
        re.search(r"\bstruct\s+ethhdr\s*\*\s*eth\s*=\s*data\s*;", text) is not None
        and re.search(r"\(\s*void\s*\*\s*\)\s*\(\s*eth\s*\+\s*1\s*\)\s*>\s*data_end", text) is not None
        and re.search(r"\bproto\s*=\s*eth->h_proto\s*;", text) is not None
        and "*(__u16 *)(data + 12)" not in text
    )


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to packet",
            ],
            functional_tests=[
                ("ipv4_drops_from_real_eth_type", lambda: frame(0x0800), 1),
                ("arp_passes_from_real_eth_type", lambda: frame(0x0806), 2),
                ("fourteen_byte_ipv4_frame_drops", fourteen_byte_ipv4_frame, 1),
            ],
            source_success_predicates=[
                ("case source invariant A", uses_typed_eth_header_for_proto),
            ],
        )
    )
