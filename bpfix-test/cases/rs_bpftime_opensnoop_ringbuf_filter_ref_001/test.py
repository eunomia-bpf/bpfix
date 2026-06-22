#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import cleanup_pin, compile_bpf, load_bpf, normalize_load_output, parse_args, pin_name_for


EXPECTED_REJECT_SUBSTRINGS = [
    "Unreleased reference",
    "alloc_insn",
]

CUSTOM_ORACLE_COVERAGE = {
    "expected_reject_substrings": [
        "Unreleased reference",
        "alloc_insn",
    ],
    "required_success_substrings": [
        "sec 'tracepoint/syscalls/sys_exit_openat'",
        "call bpf_map_lookup_elem#1",
        "call bpf_ringbuf_reserve#131",
        "call bpf_probe_read_user_str#114",
        "call bpf_ringbuf_submit#132",
        "call bpf_map_delete_elem#3",
    ],
    "required_success_predicates": [
        "opensnoop exit workflow order is preserved",
        "filtered branch preserves failed-only semantics in source",
        "filtered branch reaches cleanup without submit in verifier CFG",
    ],
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def find_matching(text: str, start: int, open_char: str, close_char: str) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index
    return None


def ret_filter_body(text: str) -> tuple[int, str] | None:
    match = re.search(r"\bif\s*\(\s*ret\s*>=\s*0\s*\)", text)
    if match is None:
        return None

    body_start = match.end()
    while body_start < len(text) and text[body_start].isspace():
        body_start += 1
    if body_start >= len(text):
        return None

    if text[body_start] == "{":
        body_end = find_matching(text, body_start, "{", "}")
        if body_end is None:
            return None
        return match.start(), text[body_start + 1 : body_end]

    semi = text.find(";", body_start)
    if semi == -1:
        return None
    return match.start(), text[body_start : semi + 1]


def filtered_source_semantics_are_preserved(text: str) -> bool:
    filter_info = ret_filter_body(text)
    if filter_info is None:
        return False

    filter_pos, body = filter_info
    reserve_pos = text.find("bpf_ringbuf_reserve")
    if reserve_pos == -1:
        return False

    body_has_submit = "bpf_ringbuf_submit" in body
    body_has_cleanup = "goto cleanup" in body or "bpf_map_delete_elem" in body
    return filter_pos < reserve_pos and body_has_cleanup and not body_has_submit and "bpf_ringbuf_reserve" not in body


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        ("keeps openat entry tracepoint", 'SEC("tracepoint/syscalls/sys_enter_openat")' in text),
        ("keeps openat exit tracepoint", 'SEC("tracepoint/syscalls/sys_exit_openat")' in text),
        ("keeps start map update", re.search(r"\bbpf_map_update_elem\s*\(\s*&start\b", text) is not None),
        ("keeps start map lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&start\b", text) is not None),
        ("keeps failed-only ret filter", re.search(r"\bret\s*>=\s*0\b", text) is not None),
        ("filtered branch preserves failed-only semantics", filtered_source_semantics_are_preserved(text)),
        ("keeps ringbuf reserve", re.search(r"\bbpf_ringbuf_reserve\s*\(\s*&rb\b", text) is not None),
        ("keeps user filename copy", re.search(r"\bbpf_probe_read_user_str\s*\(", text) is not None),
        ("keeps ringbuf submit", re.search(r"\bbpf_ringbuf_submit\s*\(", text) is not None),
        ("keeps start map cleanup", re.search(r"\bbpf_map_delete_elem\s*\(\s*&start\b", text) is not None),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def load_order_is_preserved(load_output: str) -> bool:
    lookup = load_output.find("call bpf_map_lookup_elem#1")
    reserve = load_output.find("call bpf_ringbuf_reserve#131")
    read_name = load_output.find("call bpf_probe_read_user_str#114")
    submit = load_output.find("call bpf_ringbuf_submit#132")
    delete = load_output.find("call bpf_map_delete_elem#3")
    return -1 not in {lookup, reserve, read_name, submit, delete} and lookup < reserve < read_name < submit < delete


def exit_program_log(load_output: str) -> str:
    marker = "prog 'rs_bpftime_opensnoop_exit': -- BEGIN PROG LOAD LOG --"
    start = load_output.find(marker)
    if start == -1:
        return ""
    end = load_output.find("-- END PROG LOAD LOG --", start)
    return load_output[start:end] if end != -1 else load_output[start:]


def parse_exit_raw_instructions(load_output: str) -> dict[int, str]:
    section = exit_program_log(load_output)
    live_start = section.find("Live regs before insn:")
    annotated_start = section.find("0: R1=ctx()", live_start)
    if live_start == -1 or annotated_start == -1:
        return {}

    insns: dict[int, str] = {}
    for line in section[live_start:annotated_start].splitlines():
        match = re.match(r"\s*(\d+):\s+(?:[.0-9a-fA-F]{10}\s+)?\([0-9a-f]{2}\)\s+(.*)$", line)
        if match:
            insns[int(match.group(1))] = match.group(2).strip()
    return insns


def ret_filter_branch_pcs(load_output: str) -> list[int]:
    section = exit_program_log(load_output)
    pcs: list[int] = []
    pending_filter = False
    for line in section.splitlines():
        if "; if (ret >= 0)" in line:
            pending_filter = True
            continue
        if not pending_filter:
            continue
        match = re.match(r"\s*(\d+): \([0-9a-f]{2}\) (.*)$", line)
        if match is None:
            continue
        pc = int(match.group(1))
        op = match.group(2)
        if op.startswith("if ") and "goto pc" in op:
            pcs.append(pc)
        pending_filter = False
    return pcs


def next_pc(insns: dict[int, str], pc: int) -> int | None:
    for candidate in sorted(insns):
        if candidate > pc:
            return candidate
    return None


def branch_target(pc: int, op: str) -> int | None:
    match = re.search(r"goto pc([+-]\d+)", op)
    return pc + 1 + int(match.group(1)) if match else None


def successors(insns: dict[int, str], pc: int) -> list[int]:
    op = insns.get(pc)
    if op is None or op == "exit":
        return []
    target = branch_target(pc, op)
    fallthrough = next_pc(insns, pc)
    if op.startswith("if ") and "goto pc" in op:
        return [succ for succ in [fallthrough, target] if succ is not None]
    if op.startswith("goto pc"):
        return [target] if target is not None else []
    return [fallthrough] if fallthrough is not None else []


def call_pcs(insns: dict[int, str], helper: str) -> set[int]:
    return {pc for pc, op in insns.items() if helper in op}


def filtered_successor_reaches_cleanup(
    insns: dict[int, str],
    start_pc: int,
    *,
    delete_pcs: set[int],
    submit_pcs: set[int],
    discard_pcs: set[int],
    require_discard: bool,
) -> bool:
    worklist = [(start_pc, False)]
    visited: set[tuple[int, bool]] = set()
    while worklist:
        pc, saw_discard = worklist.pop()
        state = (pc, saw_discard)
        if state in visited:
            continue
        visited.add(state)

        if pc in submit_pcs:
            continue
        saw_discard = saw_discard or pc in discard_pcs
        if pc in delete_pcs and (saw_discard or not require_discard):
            return True
        for succ in successors(insns, pc):
            worklist.append((succ, saw_discard))
    return False


def filtered_ret_path_reaches_cleanup_without_submit(load_output: str) -> bool:
    insns = parse_exit_raw_instructions(load_output)
    if not insns:
        return False

    reserve_pcs = call_pcs(insns, "call bpf_ringbuf_reserve#131")
    submit_pcs = call_pcs(insns, "call bpf_ringbuf_submit#132")
    discard_pcs = call_pcs(insns, "call bpf_ringbuf_discard#133")
    delete_pcs = call_pcs(insns, "call bpf_map_delete_elem#3")
    if not reserve_pcs or not submit_pcs or not delete_pcs:
        return False

    for branch_pc in ret_filter_branch_pcs(load_output):
        reserve_before_branch = any(pc < branch_pc for pc in reserve_pcs)
        for succ in successors(insns, branch_pc):
            if filtered_successor_reaches_cleanup(
                insns,
                succ,
                delete_pcs=delete_pcs,
                submit_pcs=submit_pcs,
                discard_pcs=discard_pcs,
                require_discard=reserve_before_branch,
            ):
                return True
    return False


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier loads openat exit tracepoint", "sec 'tracepoint/syscalls/sys_exit_openat'" in load_output),
        ("verifier sees start map lookup", "call bpf_map_lookup_elem#1" in load_output),
        ("verifier sees ringbuf reserve", "call bpf_ringbuf_reserve#131" in load_output),
        ("verifier sees filename copy", "call bpf_probe_read_user_str#114" in load_output),
        ("verifier sees ringbuf submit", "call bpf_ringbuf_submit#132" in load_output),
        ("verifier sees start map cleanup", "call bpf_map_delete_elem#3" in load_output),
        ("opensnoop exit workflow order is preserved", load_order_is_preserved(load_output)),
        (
            "filtered branch reaches cleanup without submit in verifier CFG",
            filtered_ret_path_reaches_cleanup_without_submit(load_output),
        ),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    work_dir_obj: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir is None:
        work_dir_obj = tempfile.TemporaryDirectory(prefix="bpfix-test-")
        work_dir = Path(work_dir_obj.name)
    else:
        work_dir = args.work_dir
        work_dir.mkdir(parents=True, exist_ok=True)

    source = args.source.resolve()
    obj = work_dir / "prog.o"
    pin = Path("/sys/fs/bpf") / pin_name_for(source)
    report: dict[str, object] = {
        "source": str(source),
        "expect_reject": args.expect_reject,
        "compile": None,
        "load": None,
        "source_semantics": [],
        "load_log_semantics": [],
        "passed": False,
    }

    try:
        compile_result = compile_bpf(source, obj)
        report["compile"] = compile_result.to_json()
        if compile_result.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        load_result = load_bpf(obj, pin, prog_type="tracepoint")
        report["load"] = load_result.to_json()
        normalized = normalize_load_output(load_result.output, source=source, work_dir=work_dir, obj=obj, pin=pin)
        if args.save_log is not None:
            args.save_log.write_text(normalized, encoding="utf-8")

        if args.expect_reject:
            rejected = load_result.returncode != 0 and all(
                needle in load_result.output for needle in EXPECTED_REJECT_SUBSTRINGS
            )
            report["passed"] = rejected
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if rejected else 1

        if load_result.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        source_checks = source_semantics(source)
        load_checks = load_log_semantics(load_result.output)
        report["source_semantics"] = source_checks
        report["load_log_semantics"] = load_checks
        report["passed"] = all(check["passed"] for check in source_checks + load_checks)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1
    finally:
        cleanup_pin(pin)
        if work_dir_obj is not None:
            work_dir_obj.cleanup()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
