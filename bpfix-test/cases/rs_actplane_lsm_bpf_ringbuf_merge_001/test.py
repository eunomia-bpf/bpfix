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
    "R1 invalid mem access 'ringbuf_mem_or_null'",
]

CUSTOM_ORACLE_COVERAGE = {
    "required_success_substrings": [
        "call bpf_map_lookup_elem#1",
        "call bpf_ringbuf_reserve#131",
        "call bpf_ringbuf_submit#132",
    ],
    "required_success_predicates": [
        "helper order preserves policy-event workflow",
        "event fields are written before submit",
        "deny return reaches exit",
    ],
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        ("keeps LSM bpf hook", 'SEC("lsm/bpf")' in text),
        ("does not become an XDP program", 'SEC("xdp")' not in text),
        ("keeps protected-pid map lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&protected_pids\b", text) is not None),
        ("keeps ringbuf reserve", re.search(r"\bbpf_ringbuf_reserve\s*\(\s*&events\b", text) is not None),
        ("keeps ringbuf submit", re.search(r"\bbpf_ringbuf_submit\s*\(", text) is not None),
        ("keeps deny return", re.search(r"\breturn\s+-\s*EPERM\s*;", text) is not None),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def helper_order_is_preserved(load_output: str) -> bool:
    lookup = load_output.find("call bpf_map_lookup_elem#1")
    reserve = load_output.find("call bpf_ringbuf_reserve#131")
    submit = load_output.find("call bpf_ringbuf_submit#132")
    return lookup != -1 and reserve != -1 and submit != -1 and lookup < reserve < submit


def ringbuf_event_written_before_submit(load_output: str) -> bool:
    in_annotated_trace = False
    saw_pid_store = False
    saw_cmd_store = False
    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue
        if "call bpf_ringbuf_submit#132" in line:
            return saw_pid_store and saw_cmd_store
        if re.search(r"\*\(u32 \*\)\(r\d+ \+0\) = r\d+", line):
            saw_pid_store = "ringbuf_mem" in line or saw_pid_store
        if re.search(r"\*\(u32 \*\)\(r\d+ \+4\) = r\d+", line):
            saw_cmd_store = "ringbuf_mem" in line or saw_cmd_store
    return False


def lsm_deny_return_reaches_exit(load_output: str) -> bool:
    saw_minus_eperm = False
    for line in load_output.splitlines():
        if "0xffffffff" in line:
            saw_minus_eperm = True
        if saw_minus_eperm and "(95) exit" in line:
            return True
    return False


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier loads lsm/bpf program", "sec 'lsm/bpf'" in load_output),
        ("verifier sees protected map lookup", "call bpf_map_lookup_elem#1" in load_output),
        ("verifier sees ringbuf reserve", "call bpf_ringbuf_reserve#131" in load_output),
        ("verifier sees ringbuf submit", "call bpf_ringbuf_submit#132" in load_output),
        ("helper order preserves policy-event workflow", helper_order_is_preserved(load_output)),
        ("event fields are written before submit", ringbuf_event_written_before_submit(load_output)),
        ("deny return reaches exit", lsm_deny_return_reaches_exit(load_output)),
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

        load_result = load_bpf(obj, pin, prog_type="lsm")
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
