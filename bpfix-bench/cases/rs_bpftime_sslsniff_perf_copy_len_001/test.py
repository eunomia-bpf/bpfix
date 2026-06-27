#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import cleanup_pin, compile_bpf, load_bpf, normalize_load_output, parse_args, pin_name_for


SSL_EVENT_BUF_OFFSET = 56
USER_COPY_TO_BUF_RE = re.compile(
    r"\bbpf_probe_read_user\s*\(\s*(?:&\s*)?data\s*->\s*buf(?:\s*\[\s*0\s*\])?(?:\s*\+\s*0)?\s*,"
)

EXPECTED_REJECT_SUBSTRINGS = [
    "invalid access to map value, value_size=64 off=56 size=16",
    "R1 min value is outside of the allowed memory range",
]

CUSTOM_ORACLE_COVERAGE = {
    "required_success_substrings": [
        "call bpf_map_lookup_elem#1",
        "call bpf_probe_read_user#112",
        "call bpf_map_delete_elem#3",
        "call bpf_perf_event_output#25",
    ],
    "required_success_predicates": [
        "probe-read destination is ssl_data.buf and fits",
        "perf output submits ssl_data event",
    ],
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def preserves_ssl_capture_buffer_abi(text: str) -> bool:
    return (
        re.search(r"#\s*define\s+MAX_BUF_SIZE\s+16\b", text) is not None
        and re.search(r"#\s*define\s+DATA_BUF_SIZE\s+16\b", text) is not None
        and re.search(r"\bcopy_size\s*>\s*DATA_BUF_SIZE\b", text) is None
    )


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        ("keeps SSL_read uretprobe", 'SEC("uretprobe/SSL_read")' in text),
        ("keeps bufs lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&bufs\b", text) is not None),
        ("keeps start_ns lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&start_ns\b", text) is not None),
        ("keeps ssl_data scratch lookup", re.search(r"\bbpf_map_lookup_elem\s*\(\s*&ssl_data\b", text) is not None),
        ("computes delta from timestamp map value", re.search(r"\bdelta_ns\b[^;=]*=\s*[^;]*-\s*\*", text) is not None),
        ("keeps user-memory copy into ssl_event.buf", USER_COPY_TO_BUF_RE.search(text) is not None),
        ("keeps perf-event output", re.search(r"\bbpf_perf_event_output\s*\(", text) is not None),
        ("cleans bufs map", re.search(r"\bbpf_map_delete_elem\s*\(\s*&bufs\b", text) is not None),
        ("cleans start_ns map", re.search(r"\bbpf_map_delete_elem\s*\(\s*&start_ns\b", text) is not None),
        ("case source invariant A", preserves_ssl_capture_buffer_abi(text)),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def helper_order_is_preserved(load_output: str) -> bool:
    lookups = [m.start() for m in re.finditer(r"call bpf_map_lookup_elem#1", load_output)]
    probe = load_output.find("call bpf_probe_read_user#112")
    deletes = [m.start() for m in re.finditer(r"call bpf_map_delete_elem#3", load_output)]
    output = load_output.find("call bpf_perf_event_output#25")
    return (
        len(lookups) >= 3
        and len(deletes) >= 2
        and -1 not in {probe, output}
        and lookups[0] < lookups[1] < lookups[2] < probe < deletes[0] < deletes[1] < output
    )


def parse_map_value_state(line: str, map_name: str) -> list[tuple[int, int, int]]:
    values: list[tuple[int, int, int]] = []
    for reg, body in re.findall(r"\bR(\d+)(?:_w)?=map_value\(([^)]*)\)", line):
        if f"map={map_name}" not in body:
            continue
        off_match = re.search(r"\boff=(\d+)", body)
        size_match = re.search(r"\bvs=(\d+)", body)
        if size_match is None:
            continue
        values.append((int(reg), int(off_match.group(1)) if off_match else 0, int(size_match.group(1))))
    return values


def parse_reg_maxima(line: str) -> dict[int, int]:
    maxima: dict[int, int] = {}
    for reg, value in re.findall(r"\bR(\d+)(?:_w)?=(\d+)\b", line):
        maxima[int(reg)] = int(value)
    for reg, value in re.findall(r"\bR(\d+)(?:_w)?=scalar\([^)]*umax=(0x[0-9a-fA-F]+|\d+)", line):
        maxima[int(reg)] = int(value, 0)
    return maxima


def probe_read_destination_fits_ssl_data(load_output: str) -> bool:
    in_annotated_trace = False
    ssl_ranges: dict[int, tuple[int, int]] = {}
    bufs_ptr_regs: set[int] = set()
    user_ptr_regs: set[int] = set()
    len_max: dict[int, int] = {}

    def clear_reg(reg: int) -> None:
        ssl_ranges.pop(reg, None)
        bufs_ptr_regs.discard(reg)
        user_ptr_regs.discard(reg)
        len_max.pop(reg, None)

    def clear_path_state() -> None:
        ssl_ranges.clear()
        bufs_ptr_regs.clear()
        user_ptr_regs.clear()
        len_max.clear()

    def mark_state(line: str) -> None:
        for reg, off, size in parse_map_value_state(line, "ssl_data"):
            ssl_ranges[reg] = (off, size)
        for reg, _, _ in parse_map_value_state(line, "bufs"):
            bufs_ptr_regs.add(reg)
        len_max.update(parse_reg_maxima(line))

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
            src_ssl = ssl_ranges.get(src)
            src_is_bufs = src in bufs_ptr_regs
            src_is_user = src in user_ptr_regs
            src_max = len_max.get(src)
            clear_reg(dst)
            if src_ssl is not None:
                ssl_ranges[dst] = src_ssl
            if src_is_bufs:
                bufs_ptr_regs.add(dst)
            if src_is_user:
                user_ptr_regs.add(dst)
            if src_max is not None:
                len_max[dst] = src_max

        add = re.search(r"\(07\)\s+r(\d+)\s+\+=\s+(\d+)", line)
        if add:
            reg, imm = int(add.group(1)), int(add.group(2))
            if reg in ssl_ranges:
                off, size = ssl_ranges[reg]
                ssl_ranges[reg] = (off + imm, size)

        load = re.search(r"\br(\d+)\s+=\s+\*\(u64 \*\)\(r(\d+) \+0\)", line)
        if load:
            dst, src = map(int, load.groups())
            clear_reg(dst)
            if src in bufs_ptr_regs:
                user_ptr_regs.add(dst)

        clobber = re.search(r"\((?!bf|07)\w+\)\s+r(\d+)\s+=", line)
        if clobber and not load:
            clear_reg(int(clobber.group(1)))

        mark_state(line)

        if "call bpf_probe_read_user#112" in line:
            dest = ssl_ranges.get(1)
            copy_max = len_max.get(2)
            return (
                dest is not None
                and copy_max is not None
                and 3 in user_ptr_regs
                and dest[0] == SSL_EVENT_BUF_OFFSET
                and dest[0] + copy_max <= dest[1]
            )
    return False


def perf_output_submits_ssl_data(load_output: str) -> bool:
    in_annotated_trace = False
    ssl_regs: set[int] = set()
    saw_probe = False

    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue
        if line.startswith("from "):
            ssl_regs.clear()
            saw_probe = False

        for reg, _, _ in parse_map_value_state(line, "ssl_data"):
            ssl_regs.add(reg)

        assign = re.search(r"\(bf\)\s+r(\d+)\s+=\s+r(\d+)", line)
        if assign:
            dst, src = map(int, assign.groups())
            src_is_ssl = src in ssl_regs
            ssl_regs.discard(dst)
            if src_is_ssl:
                ssl_regs.add(dst)

        clobber = re.search(r"\((?!bf)\w+\)\s+r(\d+)\s+=", line)
        if clobber:
            ssl_regs.discard(int(clobber.group(1)))

        for reg, _, _ in parse_map_value_state(line, "ssl_data"):
            ssl_regs.add(reg)

        if "call bpf_probe_read_user#112" in line:
            saw_probe = True
        if "call bpf_perf_event_output#25" in line:
            return saw_probe and 4 in ssl_regs
    return False


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier loads SSL_read uretprobe", "sec 'uretprobe/SSL_read'" in load_output),
        ("verifier sees at least three map lookups", len(re.findall(r"call bpf_map_lookup_elem#1", load_output)) >= 3),
        ("verifier sees user-memory copy", "call bpf_probe_read_user#112" in load_output),
        ("verifier sees both map cleanups", len(re.findall(r"call bpf_map_delete_elem#3", load_output)) >= 2),
        ("verifier sees perf-event output", "call bpf_perf_event_output#25" in load_output),
        ("helper order preserves sslsniff exit workflow", helper_order_is_preserved(load_output)),
        ("probe-read destination is ssl_data.buf and fits", probe_read_destination_fits_ssl_data(load_output)),
        ("perf output submits ssl_data event", perf_output_submits_ssl_data(load_output)),
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

        load_result = load_bpf(obj, pin, prog_type="kprobe")
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
