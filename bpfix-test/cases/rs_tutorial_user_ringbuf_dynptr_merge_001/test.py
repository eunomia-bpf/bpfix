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
    "invalid mem access 'mem_or_null'",
]

CUSTOM_ORACLE_COVERAGE = {
    "required_success_substrings": [
        "call bpf_user_ringbuf_drain#209",
        "call bpf_dynptr_data#203",
        "call bpf_ringbuf_reserve#131",
        "call bpf_ringbuf_submit#132",
    ],
    "required_success_predicates": [
        "dynptr payload is read only after a non-null verifier proof",
        "kernel ringbuf record is submitted from the reserved reference",
    ],
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        ("keeps syscall-exit tracepoint drain", 'SEC("tracepoint/syscalls/sys_exit_kill")' in text),
        ("keeps user ringbuf map", "BPF_MAP_TYPE_USER_RINGBUF" in text and "user_ringbuf" in text),
        ("keeps kernel ringbuf map", "BPF_MAP_TYPE_RINGBUF" in text and "kernel_ringbuf" in text),
        ("keeps user-ringbuf drain helper", re.search(r"\bbpf_user_ringbuf_drain\s*\(", text) is not None),
        (
            "keeps dynptr payload consumption",
            re.search(r"\bbpf_dynptr_data\s*\(", text) is not None
            or re.search(r"\bbpf_dynptr_read\s*\(", text) is not None,
        ),
        ("keeps kernel ringbuf reserve", re.search(r"\bbpf_ringbuf_reserve\s*\(\s*&kernel_ringbuf\b", text) is not None),
        ("keeps kernel ringbuf submit", re.search(r"\bbpf_ringbuf_submit\s*\(", text) is not None),
        ("keeps current pid attribution", "bpf_get_current_pid_tgid" in text and "current_pid" in text),
        (
            "keeps user payload field propagation",
            re.search(r"\bout\s*->\s*op\s*=\s*\w+\s*(?:->|\.)\s*op\b", text) is not None
            and re.search(r"\bout\s*->\s*comm\b", text) is not None
            and re.search(r"\w+\s*(?:->|\.)\s*comm\b", text) is not None,
        ),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def helper_order_is_preserved(load_output: str) -> bool:
    drain = load_output.find("call bpf_user_ringbuf_drain#209")
    data = load_output.find("call bpf_dynptr_data#203")
    read = load_output.find("call bpf_dynptr_read#201")
    reserve = load_output.find("call bpf_ringbuf_reserve#131")
    submit = load_output.find("call bpf_ringbuf_submit#132")
    payload = data if data != -1 else read
    return -1 not in {drain, payload, reserve, submit} and drain < payload < reserve < submit


def dynptr_payload_reads_after_proof(load_output: str) -> bool:
    in_annotated_trace = False
    payload_regs: set[str] = set()
    ringbuf_regs: set[str] = set()
    payload_value_regs: dict[str, int] = {}
    stack_value_regs: dict[str, int] = {}
    copied_pairs: set[tuple[int, int]] = set()
    saw_dynptr_data = False
    saw_dynptr_read = False
    dynptr_read_success_checked = False
    awaiting_dynptr_read_check = False
    dynptr_read_stack_base: int | None = None
    window: list[str] = []
    for line in load_output.splitlines():
        if not line.strip():
            payload_regs = set()
            ringbuf_regs = set()
            payload_value_regs = {}
            stack_value_regs = {}
            window.append(line)
            continue
        if line.startswith("0: R1=") or line.startswith("from "):
            in_annotated_trace = True
            payload_regs = set()
            ringbuf_regs = set()
            payload_value_regs = {}
            stack_value_regs = {}
            dynptr_read_stack_base = None
        if not in_annotated_trace:
            window.append(line)
            continue

        if "call bpf_dynptr_data#203" in line:
            saw_dynptr_data = True
        if "call bpf_dynptr_read#201" in line:
            saw_dynptr_read = True
            awaiting_dynptr_read_check = True
            context = "\n".join(window[-10:] + [line])
            base_match = re.search(r"\bR1(?:_w)?=fp-(\d+)\b", context)
            if base_match is None:
                base_match = re.search(r"\br1\s*\+=\s*-(\d+)\b", context)
            size_match = re.search(r"\bR2(?:_w)?=24\b", context)
            dynptr_read_stack_base = int(base_match.group(1)) if base_match and size_match else None
        elif awaiting_dynptr_read_check and re.search(r"\bif r0 != 0x0 goto\b", line):
            dynptr_read_success_checked = True
            awaiting_dynptr_read_check = False
        elif awaiting_dynptr_read_check and "call bpf_ringbuf_reserve#131" in line:
            awaiting_dynptr_read_check = False

        for register, state in re.findall(r"\bR(\d+)(?:_w)?=([^\s;]+)", line):
            if state.startswith("mem(") and "sz=24" in state:
                payload_regs.add(register)
            else:
                payload_regs.discard(register)
            if state.startswith("ringbuf_mem(") and "sz=24" in state:
                ringbuf_regs.add(register)
            else:
                ringbuf_regs.discard(register)

        payload_load = re.search(r"\br(\d+)\s*=\s*\*\(u(?:32|64) \*\)\(r(\d+) \+(\d+)\)", line)
        stack_load = re.search(r"\br(\d+)\s*=\s*\*\(u(?:32|64) \*\)\(r10 -(\d+)\)", line)
        reg_copy = re.search(r"\br(\d+)\s*=\s*r(\d+)\b", line)
        high_half = re.search(r"\br(\d+)\s*>>=\s*32\b", line)
        assignment = re.search(r"\)\s*r(\d+)\s*=", line)

        if payload_load is not None and payload_load.group(2) in payload_regs:
            payload_value_regs[payload_load.group(1)] = int(payload_load.group(3))
        elif stack_load is not None and dynptr_read_stack_base is not None:
            stack_slot = int(stack_load.group(2))
            payload_offset = dynptr_read_stack_base - stack_slot
            if 0 <= payload_offset <= 20:
                stack_value_regs[stack_load.group(1)] = payload_offset
            else:
                stack_value_regs.pop(stack_load.group(1), None)
                payload_value_regs.pop(stack_load.group(1), None)
        elif reg_copy is not None:
            dst, src = reg_copy.group(1), reg_copy.group(2)
            if src in payload_value_regs:
                payload_value_regs[dst] = payload_value_regs[src]
            else:
                payload_value_regs.pop(dst, None)
            if src in stack_value_regs:
                stack_value_regs[dst] = stack_value_regs[src]
            else:
                stack_value_regs.pop(dst, None)
        elif high_half is not None:
            register = high_half.group(1)
            if register in payload_value_regs:
                payload_value_regs[register] += 4
            if register in stack_value_regs:
                stack_value_regs[register] += 4
        elif assignment is not None:
            dst = assignment.group(1)
            payload_value_regs.pop(dst, None)
            stack_value_regs.pop(dst, None)

        record_store = re.search(r"\*\(u(?:32|64) \*\)\(r(\d+) \+(\d+)\) = r(\d+)", line)
        if record_store is not None and record_store.group(1) in ringbuf_regs:
            record_offset = int(record_store.group(2))
            src = record_store.group(3)
            payload_offset = payload_value_regs.get(src)
            if payload_offset is None:
                payload_offset = stack_value_regs.get(src)
            if payload_offset is not None:
                copied_pairs.add((payload_offset, record_offset))

        window.append(line)

    required_pairs = {(4, 4), (8, 8), (12, 12), (16, 16), (20, 20)}
    payload_copied = required_pairs.issubset(copied_pairs)
    return (saw_dynptr_data and payload_copied) or (
        saw_dynptr_read and dynptr_read_success_checked and payload_copied
    )


def ringbuf_submit_uses_reserved_record(load_output: str) -> bool:
    window: list[str] = []
    for line in load_output.splitlines():
        if "call bpf_ringbuf_submit#132" in line:
            context = "\n".join(window[-12:] + [line])
            if "R1" not in context:
                window.append(line)
                continue
            return (
                re.search(r"\bR1(?:_w)?=ringbuf_mem\([^)]*ref_obj_id=\d+[^)]*sz=24\)", context)
                is not None
            )
        window.append(line)
    return False


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier loads syscall-exit tracepoint", "sec 'tracepoint/syscalls/sys_exit_kill'" in load_output),
        ("verifier sees user-ringbuf drain", "call bpf_user_ringbuf_drain#209" in load_output),
        ("verifier sees dynptr payload helper", "call bpf_dynptr_data#203" in load_output or "call bpf_dynptr_read#201" in load_output),
        ("verifier sees kernel ringbuf reserve", "call bpf_ringbuf_reserve#131" in load_output),
        ("verifier sees kernel ringbuf submit", "call bpf_ringbuf_submit#132" in load_output),
        ("helper order preserves drain-payload-emit workflow", helper_order_is_preserved(load_output)),
        ("dynptr payload is read only after a non-null verifier proof", dynptr_payload_reads_after_proof(load_output)),
        ("kernel ringbuf record is submitted from the reserved reference", ringbuf_submit_uses_reserved_record(load_output)),
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
