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
    "program of this type cannot use helper bpf_get_stack#67",
]


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        (
            "uses syscall-exit tracepoint entry point",
            bool(
                re.search(
                    r'SEC\("(tp|tracepoint)/syscalls/sys_exit_openat"\)\s*'
                    r'int\s+\w+\s*\(\s*struct\s+trace_event_raw_sys_exit\s*\*\s*\w+\s*\)',
                    text,
                    flags=re.DOTALL,
                )
            ),
        ),
        ("does not remain an XDP program", 'SEC("xdp")' not in text),
        ("preserves live bpf_get_stack user-stack call", re.search(r"bpf_get_stack\s*\([^;]*BPF_F_USER_STACK", text, re.DOTALL) is not None),
        ("keeps perf-event output call", re.search(r"\bbpf_perf_event_output\s*\(", text) is not None),
        ("keeps start map lookup call", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&start\b", text) is not None),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def bpf_get_stack_uses_user_stack_flag(load_output: str) -> bool:
    window: list[str] = []
    for line in load_output.splitlines():
        if "call bpf_get_stack#67" in line:
            return any(re.search(r"\br4\s*=\s*256\b", candidate) for candidate in window[-6:])
        window.append(line)
    return False


def helper_order_is_preserved(load_output: str) -> bool:
    map_lookup = load_output.find("call bpf_map_lookup_elem#1")
    stack = load_output.find("call bpf_get_stack#67")
    perf = load_output.find("call bpf_perf_event_output#25")
    return map_lookup != -1 and stack != -1 and perf != -1 and map_lookup < stack < perf


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier sees start-map lookup", "call bpf_map_lookup_elem#1" in load_output),
        ("verifier sees bpf_get_stack helper", "call bpf_get_stack#67" in load_output),
        ("bpf_get_stack uses BPF_F_USER_STACK flag", bpf_get_stack_uses_user_stack_flag(load_output)),
        ("verifier sees perf-event output helper", "call bpf_perf_event_output#25" in load_output),
        ("helper order preserves lookup-stack-output workflow", helper_order_is_preserved(load_output)),
        (
            "verifier loads tracepoint program",
            "sec 'tracepoint/syscalls/sys_exit_openat'" in load_output
            or "sec 'tp/syscalls/sys_exit_openat'" in load_output,
        ),
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

        load_result = load_bpf(obj, pin, prog_type=None)
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
