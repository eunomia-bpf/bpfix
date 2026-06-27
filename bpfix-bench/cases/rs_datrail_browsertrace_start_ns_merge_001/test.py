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
    "invalid mem access 'map_value_or_null'",
]

CUSTOM_ORACLE_COVERAGE = {
    "required_success_substrings": [
        "call bpf_map_lookup_elem#1",
        "call bpf_ringbuf_reserve#131",
        "call bpf_probe_read_user#112",
        "call bpf_map_delete_elem#3",
        "call bpf_ringbuf_submit#132",
    ],
    "required_success_predicates": [
        "start timestamp proof dominates delta read",
        "bounded user copy is submitted and both maps are cleaned up",
    ],
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        ("keeps syscall-exit read tracepoint", 'SEC("tp/syscalls/sys_exit_read")' in text),
        ("keeps start_ns lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&start_ns\b", text) is not None),
        ("keeps bufs lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&bufs\b", text) is not None),
        ("computes delta from timestamp map value", re.search(r"\bdelta_ns\b[^;=]*=\s*[^;]*-\s*\*", text) is not None),
        ("keeps bounded user-memory copy", re.search(r"\bbpf_probe_read_user\s*\(", text) is not None and "MAX_BUF_SIZE" in text),
        ("keeps ringbuf reserve", re.search(r"\bbpf_ringbuf_reserve\s*\(\s*&rb\b", text) is not None),
        ("keeps ringbuf submit", re.search(r"\bbpf_ringbuf_submit\s*\(", text) is not None),
        ("cleans bufs map", re.search(r"\bbpf_map_delete_elem\s*\(\s*&bufs\b", text) is not None),
        ("cleans start_ns map", re.search(r"\bbpf_map_delete_elem\s*\(\s*&start_ns\b", text) is not None),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def helper_order_is_preserved(load_output: str) -> bool:
    lookups = [m.start() for m in re.finditer(r"call bpf_map_lookup_elem#1", load_output)]
    reserve = load_output.find("call bpf_ringbuf_reserve#131")
    probe = load_output.find("call bpf_probe_read_user#112")
    deletes = [m.start() for m in re.finditer(r"call bpf_map_delete_elem#3", load_output)]
    submit = load_output.find("call bpf_ringbuf_submit#132")
    return (
        len(lookups) >= 2
        and len(deletes) >= 2
        and -1 not in {reserve, probe, submit}
        and lookups[0] < lookups[1] < reserve < probe < deletes[0] < deletes[1] < submit
    )


def start_ns_value_read_before_delta_store(load_output: str) -> bool:
    in_annotated_trace = False
    start_ptr_regs: set[int] = set()
    start_value_regs: set[int] = set()
    delta_regs: set[int] = set()
    ringbuf_regs: set[int] = set()

    def clear_reg(reg: int) -> None:
        start_ptr_regs.discard(reg)
        start_value_regs.discard(reg)
        delta_regs.discard(reg)
        ringbuf_regs.discard(reg)

    def clear_path_state() -> None:
        start_ptr_regs.clear()
        start_value_regs.clear()
        delta_regs.clear()
        ringbuf_regs.clear()

    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue
        if line.startswith("from "):
            clear_path_state()

        for reg in re.findall(r"\bR(\d+)(?:_w)?=map_value\(map=start_ns\b", line):
            start_ptr_regs.add(int(reg))
        for reg in re.findall(r"\bR(\d+)(?:_w)?=ringbuf_mem\b", line):
            ringbuf_regs.add(int(reg))

        assign = re.search(r"\(bf\)\s+r(\d+)\s+=\s+r(\d+)", line)
        if assign:
            dst, src = map(int, assign.groups())
            src_is_start_ptr = src in start_ptr_regs
            src_is_start_value = src in start_value_regs
            src_is_delta = src in delta_regs
            src_is_ringbuf = src in ringbuf_regs
            clear_reg(dst)
            if src_is_start_ptr:
                start_ptr_regs.add(dst)
            if src_is_start_value:
                start_value_regs.add(dst)
            if src_is_delta:
                delta_regs.add(dst)
            if src_is_ringbuf:
                ringbuf_regs.add(dst)

        load = re.search(r"\br(\d+)\s+=\s+\*\(u64 \*\)\(r(\d+) \+0\)", line)
        if load:
            dst, src = map(int, load.groups())
            clear_reg(dst)
            if src in start_ptr_regs:
                start_value_regs.add(dst)

        sub = re.search(r"\br(\d+)\s+-=\s+r(\d+)", line)
        if sub:
            dst, src = map(int, sub.groups())
            clear_reg(dst)
            if src in start_value_regs:
                delta_regs.add(dst)

        clobber = re.search(r"\((?!bf\))\w+\)\s+r(\d+)\s+=", line)
        if clobber and not load:
            clear_reg(int(clobber.group(1)))

        store = re.search(r"\*\(u64 \*\)\(r(\d+) \+0\) = r(\d+)", line)
        if store:
            dst_ptr, src = map(int, store.groups())
            if dst_ptr in ringbuf_regs and src in delta_regs:
                return True
    return False


def bounded_copy_uses_bufs_value(load_output: str) -> bool:
    in_annotated_trace = False
    bufs_ptr_regs: set[int] = set()
    user_ptr_regs: set[int] = set()
    ringbuf_dest_regs: set[int] = set()
    bounded_len_regs: set[int] = set()

    def clear_reg(reg: int) -> None:
        bufs_ptr_regs.discard(reg)
        user_ptr_regs.discard(reg)
        ringbuf_dest_regs.discard(reg)
        bounded_len_regs.discard(reg)

    def clear_path_state() -> None:
        bufs_ptr_regs.clear()
        user_ptr_regs.clear()
        ringbuf_dest_regs.clear()
        bounded_len_regs.clear()

    def mark_state(line: str) -> None:
        for reg in re.findall(r"\bR(\d+)(?:_w)?=map_value\(map=bufs\b", line):
            bufs_ptr_regs.add(int(reg))
        for reg in re.findall(r"\bR(\d+)(?:_w)?=ringbuf_mem\([^)]*off=24,[^)]*sz=40\)", line):
            ringbuf_dest_regs.add(int(reg))
        for reg in re.findall(r"\bR(\d+)(?:_w)?=16\b", line):
            bounded_len_regs.add(int(reg))

    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue
        if line.startswith("from "):
            clear_path_state()

        mark_state(line)

        assign = re.search(r"\(bf\)\s+r(\d+)\s+=\s+r(\d+)", line)
        if assign:
            dst, src = map(int, assign.groups())
            src_is_bufs_ptr = src in bufs_ptr_regs
            src_is_user_ptr = src in user_ptr_regs
            src_is_ringbuf_dest = src in ringbuf_dest_regs
            src_is_bounded_len = src in bounded_len_regs
            clear_reg(dst)
            if src_is_bufs_ptr:
                bufs_ptr_regs.add(dst)
            if src_is_user_ptr:
                user_ptr_regs.add(dst)
            if src_is_ringbuf_dest:
                ringbuf_dest_regs.add(dst)
            if src_is_bounded_len:
                bounded_len_regs.add(dst)

        load = re.search(r"\br(\d+)\s+=\s+\*\(u64 \*\)\(r(\d+) \+0\)", line)
        if load:
            dst, src = map(int, load.groups())
            clear_reg(dst)
            if src in bufs_ptr_regs:
                user_ptr_regs.add(dst)

        clobber = re.search(r"\((?!bf\))\w+\)\s+r(\d+)\s+=", line)
        if clobber and not load:
            clear_reg(int(clobber.group(1)))

        mark_state(line)
        if "call bpf_probe_read_user#112" in line:
            return 3 in user_ptr_regs and 1 in ringbuf_dest_regs and 2 in bounded_len_regs
    return False


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier loads sys_exit_read tracepoint", "sec 'tp/syscalls/sys_exit_read'" in load_output),
        ("verifier sees two map lookups", len(re.findall(r"call bpf_map_lookup_elem#1", load_output)) >= 2),
        ("verifier sees ringbuf reserve", "call bpf_ringbuf_reserve#131" in load_output),
        ("verifier sees user-memory copy", "call bpf_probe_read_user#112" in load_output),
        ("verifier sees both map cleanups", len(re.findall(r"call bpf_map_delete_elem#3", load_output)) >= 2),
        ("verifier sees ringbuf submit", "call bpf_ringbuf_submit#132" in load_output),
        ("helper order preserves browsertrace exit workflow", helper_order_is_preserved(load_output)),
        ("start timestamp proof dominates delta read", start_ns_value_read_before_delta_store(load_output)),
        ("bounded user copy reads saved buffer pointer", bounded_copy_uses_bufs_value(load_output)),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    work_dir_obj: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir is None:
        work_dir_obj = tempfile.TemporaryDirectory(prefix="bpfix-bench-")
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
