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
    "invalid access to memory, mem_size=24 off=16 size=16",
    "R1 min value is outside of the allowed memory range",
]

CUSTOM_ORACLE_COVERAGE = {
    "required_success_substrings": [
        "call bpf_map_lookup_elem#1",
        "call bpf_ringbuf_reserve#131",
        "call bpf_probe_read_user#112",
        "call bpf_ringbuf_submit#132",
        "call bpf_map_delete_elem#3",
    ],
    "required_success_predicates": [
        "probe-read destination range fits reserved event",
        "event metadata and user copy are submitted",
    ],
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        ("keeps syscall-exit read tracepoint", 'SEC("tp/syscalls/sys_exit_read")' in text),
        ("does not become an XDP program", 'SEC("xdp")' not in text),
        ("keeps io_args lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&io_args\b", text) is not None),
        ("keeps ringbuf reserve", re.search(r"\bbpf_ringbuf_reserve\s*\(\s*&rb\b", text) is not None),
        ("keeps user-memory copy", re.search(r"\bbpf_probe_read_user\s*\(", text) is not None),
        ("keeps ringbuf submit", re.search(r"\bbpf_ringbuf_submit\s*\(", text) is not None),
        ("keeps io_args cleanup", re.search(r"\bbpf_map_delete_elem\s*\(\s*&io_args\b", text) is not None),
        (
            "keeps original copy length intent and clamps to event buffer",
            re.search(r"\bcopy_size\s*=\s*16\b", text) is not None
            and re.search(r"\bcopy_size\s*>\s*sizeof\s*\(\s*event\s*->\s*buf\s*\)", text) is not None
            and re.search(r"\bcopy_size\s*=\s*sizeof\s*\(\s*event\s*->\s*buf\s*\)", text) is not None,
        ),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def helper_order_is_preserved(load_output: str) -> bool:
    lookup = load_output.find("call bpf_map_lookup_elem#1")
    reserve = load_output.find("call bpf_ringbuf_reserve#131")
    probe = load_output.find("call bpf_probe_read_user#112")
    submit = load_output.find("call bpf_ringbuf_submit#132")
    delete = load_output.find("call bpf_map_delete_elem#3")
    return -1 not in {lookup, reserve, probe, submit, delete} and lookup < reserve < probe < submit < delete


def probe_read_destination_fits_event(load_output: str) -> bool:
    in_annotated_trace = False
    window: list[str] = []
    saw_probe = False
    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
            window = []
        if not in_annotated_trace:
            continue
        if "call bpf_probe_read_user#112" in line:
            saw_probe = True
            context = "\n".join(window[-8:] + [line])
            ranges = [
                (int(off or "0"), int(size))
                for off, size in re.findall(r"\bR1(?:_w)?=ringbuf_mem\([^)]*(?:off=(\d+),)?sz=(\d+)\)", context)
            ]
            lengths = [int(value) for value in re.findall(r"\bR2_w=(\d+)\b|\br2 = (\d+)\b", context) for value in value if value]
            if not ranges or not lengths:
                return False
            offset, event_size = ranges[-1]
            copy_len = lengths[-1]
            return copy_len > 0 and offset + copy_len <= event_size
        window.append(line)
    return saw_probe


def submitted_event_contains_metadata_and_copy(load_output: str) -> bool:
    in_annotated_trace = False
    stores = {0: False, 4: False, 8: False, 12: False}
    saw_probe = False
    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue
        if "call bpf_probe_read_user#112" in line:
            saw_probe = True
        if "call bpf_ringbuf_submit#132" in line:
            return saw_probe and all(stores.values())
        store = re.search(r"\*\((?:u32|u8) \*\)\(r\d+ \+(\d+)\) =", line)
        if store is not None:
            offset = int(store.group(1))
            if offset in stores and "ringbuf_mem" in line:
                stores[offset] = True
    return False


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier loads sys_exit_read tracepoint", "sec 'tp/syscalls/sys_exit_read'" in load_output),
        ("verifier sees io_args lookup", "call bpf_map_lookup_elem#1" in load_output),
        ("verifier sees ringbuf reserve", "call bpf_ringbuf_reserve#131" in load_output),
        ("verifier sees user-memory copy", "call bpf_probe_read_user#112" in load_output),
        ("verifier sees ringbuf submit", "call bpf_ringbuf_submit#132" in load_output),
        ("verifier sees io_args delete", "call bpf_map_delete_elem#3" in load_output),
        ("helper order preserves stdiocap workflow", helper_order_is_preserved(load_output)),
        ("probe-read destination range fits reserved event", probe_read_destination_fits_event(load_output)),
        ("event metadata and user copy are submitted", submitted_event_contains_metadata_and_copy(load_output)),
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
