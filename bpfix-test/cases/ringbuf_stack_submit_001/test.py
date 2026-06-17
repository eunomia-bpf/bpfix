#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import run_case


def ethernet_frame() -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + (b"\x00" * 64)


def ringbuf_refs_for_register(state: str, register: str) -> set[str]:
    return set(
        re.findall(rf"\bR{register}(?:_w)?=ringbuf_mem\(ref_obj_id=(\d+),", state)
    )


def writes_mark_to_ringbuf_mem(load_output: str) -> bool:
    in_annotated_trace = False
    written_refs: set[str] = set()
    r1_refs: set[str] = set()
    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
            continue
        if not in_annotated_trace:
            continue
        state = line.partition(";")[2]
        if re.search(r"\bR1(?:_w)?=", state):
            r1_refs = ringbuf_refs_for_register(state, "1")
        if "call bpf_ringbuf_submit#132" in line:
            return bool(written_refs & r1_refs)
        store = re.search(r"\*\(u32 \*\)\(r(\d+)\s*[+-]\d+\)\s*=\s*r\d+", line)
        if store is None:
            continue
        written_refs.update(ringbuf_refs_for_register(state, store.group(1)))
    return False


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "R1 type=fp expected=ringbuf_mem",
            ],
            functional_tests=[
                ("xdp_pass", ethernet_frame, 2),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "R0_w=ringbuf_mem_or_null",
                "call bpf_ringbuf_submit#132",
            ],
            required_success_predicates=[
                ("write mark field into ringbuf_mem before submit", writes_mark_to_ringbuf_mem),
            ],
        )
    )
