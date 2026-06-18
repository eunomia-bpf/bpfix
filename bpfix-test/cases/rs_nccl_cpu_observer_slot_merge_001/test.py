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
        "call bpf_ktime_get_ns#5",
        "call bpf_get_smp_processor_id#8",
        "call bpf_map_update_elem#2",
    ],
    "required_success_predicates": [
        "per-cpu slot map value is updated after a non-null proof",
        "state_map update publishes a stack-built contention state",
    ],
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        ("keeps sched_switch tracepoint", 'SEC("tp/sched/sched_switch")' in text),
        ("does not become packet program", 'SEC("xdp")' not in text and 'SEC("tc")' not in text),
        ("keeps config map lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&config_map\b", text) is not None),
        ("keeps per-cpu slot map lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&percpu_slot_map\b", text) is not None),
        ("keeps target-keyed per-cpu slots", "BPF_MAP_TYPE_PERCPU_HASH" in text and "slot_key" in text),
        ("keeps mmapable state map", "BPF_F_MMAPABLE" in text and "state_map" in text),
        ("keeps current task filter", "bpf_get_current_pid_tgid" in text and "target_pid" in text),
        ("keeps scheduler timestamp and cpu helpers", "bpf_ktime_get_ns" in text and "bpf_get_smp_processor_id" in text),
        ("keeps contention state publish", re.search(r"\bbpf_map_update_elem\s*\(\s*&state_map\b", text) is not None),
        ("keeps rolling-window fields", all(field in text for field in ["window_start_ns", "switches_in_window", "cpu_seen_mask"])),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def helper_order_is_preserved(load_output: str) -> bool:
    first_lookup = load_output.find("call bpf_map_lookup_elem#1")
    time_call = load_output.find("call bpf_ktime_get_ns#5")
    cpu_call = load_output.find("call bpf_get_smp_processor_id#8")
    update = load_output.find("call bpf_map_update_elem#2")
    return -1 not in {first_lookup, time_call, cpu_call, update} and first_lookup < time_call < cpu_call < update


def slot_updates_after_map_value_proof(load_output: str) -> bool:
    in_annotated_trace = False
    map_value_regs: set[str] = set()
    stored_offsets: set[int] = set()
    saw_lookup = False
    for line in load_output.splitlines():
        if not line.strip():
            map_value_regs = set()
            continue
        if line.startswith("0: R1=") or line.startswith("from "):
            in_annotated_trace = True
            map_value_regs = set()
        if not in_annotated_trace:
            continue

        if "call bpf_map_lookup_elem#1" in line:
            saw_lookup = True
        for register, state in re.findall(r"\bR(\d+)(?:_w)?=([^\s;]+)", line):
            if state.startswith("map_value(") and "map=percpu_slot_map" in state:
                map_value_regs.add(register)
            else:
                map_value_regs.discard(register)

        store = re.search(r"\*\(u(?:32|64) \*\)\(r(\d+) \+(\d+)\) =", line)
        if store is not None and store.group(1) in map_value_regs:
            stored_offsets.add(int(store.group(2)))

    return saw_lookup and {0, 8, 12}.issubset(stored_offsets)


def state_map_update_uses_stack_state(load_output: str) -> bool:
    window: list[str] = []
    saw_update = False
    for line in load_output.splitlines():
        if "call bpf_map_update_elem#2" in line:
            saw_update = True
            context = "\n".join(window[-16:] + [line])
            r1_state_map = (
                re.search(r"\bR1(?:_w)?=map_ptr\(map=state_map\b", context) is not None
            )
            r3_stack = re.search(r"\bR3(?:_w)?=fp-?\d+", context) is not None
            stack_stores = len(re.findall(r"\*\(u(?:8|32|64) \*\)\(r10 -\d+\) =", context))
            if r1_state_map and r3_stack and stack_stores >= 3:
                return True
        window.append(line)
    return saw_update and False


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier loads sched_switch tracepoint", "sec 'tp/sched/sched_switch'" in load_output),
        ("verifier sees map lookup helper", "call bpf_map_lookup_elem#1" in load_output),
        ("verifier sees ktime helper", "call bpf_ktime_get_ns#5" in load_output),
        ("verifier sees cpu helper", "call bpf_get_smp_processor_id#8" in load_output),
        ("verifier sees state publish helper", "call bpf_map_update_elem#2" in load_output),
        ("helper order preserves observer workflow", helper_order_is_preserved(load_output)),
        ("per-cpu slot map value is updated after a non-null proof", slot_updates_after_map_value_proof(load_output)),
        ("state_map update publishes a stack-built contention state", state_map_update_uses_stack_state(load_output)),
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
