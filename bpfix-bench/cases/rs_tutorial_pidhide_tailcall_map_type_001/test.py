#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import cleanup_pin_tree
from bpf_case import compile_bpf
from bpf_case import ensure_pin_tree
from bpf_case import parse_args
from bpf_case import pin_name_for
from bpf_case import run
from bpf_case import run_pinned
from bpf_case import split_tool


EXPECTED_REJECT_SUBSTRINGS = [
    "kernel subsystem misconfigured verifier",
    "call bpf_tail_call#12",
]

CUSTOM_ORACLE_COVERAGE = {
    "expected_reject_substrings": [
        "kernel subsystem misconfigured verifier",
        "call bpf_tail_call#12",
    ],
    "functional_tests": [
        "marker_tail_calls_to_drop_target",
        "non_marker_falls_back_to_pass",
    ],
    "required_success_substrings": [],
    "required_success_predicates": [
        "tail-call helper uses a prog-array map and slot 1 target program is loaded",
    ],
}


def normalize_output(output: str, source: Path, work_dir: Path, obj: Path, prog_dir: Path, map_dir: Path) -> str:
    normalized = output
    replacements = {
        str(source): "buggy.bpf.c",
        str(work_dir): "<work-dir>",
        str(obj): "<object>",
        str(prog_dir): "<bpffs-prog-dir>",
        str(map_dir): "<bpffs-map-dir>",
    }
    for old, new in replacements.items():
        normalized = normalized.replace(old, new)
    normalized = re.sub(r"/tmp/bpfix-bench-[A-Za-z0-9_.-]+", "<work-dir>", normalized)
    normalized = re.sub(r"0xffff[0-9a-fA-F]+", "0xffff000000000000", normalized)
    normalized = re.sub(r"fd=\d+", "fd=0", normalized)
    normalized = re.sub(r"verification time \d+ usec", "verification time 0 usec", normalized)
    return normalized


def loadall_bpf(obj: Path, prog_dir: Path, map_dir: Path):
    bpftool = split_tool("BPFTOOL", "sudo bpftool")
    return run(
        [
            *bpftool,
            "-d",
            "prog",
            "loadall",
            str(obj),
            str(prog_dir),
            "type",
            "xdp",
            "pinmaps",
            str(map_dir),
        ]
    )


def pinned_prog_id(path: Path) -> tuple[int | None, object]:
    bpftool = split_tool("BPFTOOL", "sudo bpftool")
    result = run([*bpftool, "-j", "prog", "show", "pinned", str(path)])
    if result.returncode != 0:
        return None, result.to_json()
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, result.to_json()
    return int(payload["id"]), result.to_json()


def update_tail_slot(map_dir: Path, target_id: int):
    bpftool = split_tool("BPFTOOL", "sudo bpftool")
    return run(
        [
            *bpftool,
            "map",
            "update",
            "pinned",
            str(map_dir / "map_prog_array"),
            "key",
            "01",
            "00",
            "00",
            "00",
            "value",
            "id",
            str(target_id),
        ]
    )


def tailcall_contract_is_visible(load_output: str) -> bool:
    helper = load_output.find("call bpf_tail_call#12")
    target = load_output.find("prog 'tail_target_drop': -- BEGIN PROG LOAD LOG --")
    return (
        "map 'map_prog_array': found type = 3." in load_output
        and helper != -1
        and target != -1
        and helper < target
        and re.search(r"\br3 = 1\b", load_output[:helper]) is not None
    )


def packet(byte: int) -> bytes:
    return bytes([byte]) + (b"\x00" * 13)


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
    base = Path("/sys/fs/bpf") / pin_name_for(source)
    prog_dir = Path(f"{base}_progs")
    map_dir = Path(f"{base}_maps")
    report: dict[str, object] = {
        "source": str(source),
        "expect_reject": args.expect_reject,
        "compile": None,
        "load": None,
        "map_setup": [],
        "functional": [],
        "success_log_checks": [],
        "passed": False,
    }

    try:
        compile_result = compile_bpf(source, obj)
        report["compile"] = compile_result.to_json()
        if compile_result.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        setup_results = report["map_setup"]
        assert isinstance(setup_results, list)
        setup_results.append(ensure_pin_tree(prog_dir).to_json())
        setup_results.append(ensure_pin_tree(map_dir).to_json())
        if any(result["returncode"] != 0 for result in setup_results):
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        load_result = loadall_bpf(obj, prog_dir, map_dir)
        report["load"] = load_result.to_json()
        if args.save_log is not None:
            args.save_log.write_text(
                normalize_output(load_result.output, source, work_dir, obj, prog_dir, map_dir),
                encoding="utf-8",
            )

        if args.expect_reject:
            report["passed"] = load_result.returncode != 0 and all(
                needle in load_result.output for needle in EXPECTED_REJECT_SUBSTRINGS
            )
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["passed"] else 1

        if load_result.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        target_id, show_result = pinned_prog_id(prog_dir / "tail_target_drop")
        setup_results.append({"target_prog_show": show_result})
        if target_id is None:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1
        setup_results.append(update_tail_slot(map_dir, target_id).to_json())
        if setup_results[-1]["returncode"] != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        checks = [
            {
                "kind": "predicate",
                "name": "tail-call helper uses a prog-array map and slot 1 target program is loaded",
                "passed": tailcall_contract_is_visible(load_result.output),
            }
        ]
        report["success_log_checks"] = checks
        if not all(check["passed"] for check in checks):
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        for name, data, expected in [
            ("marker_tail_calls_to_drop_target", packet(0xaa), 1),
            ("non_marker_falls_back_to_pass", packet(0xbb), 2),
        ]:
            actual, run_result = run_pinned(prog_dir / "entry_tailcall_dispatch", data)
            entry = {
                "name": name,
                "expected_retval": expected,
                "actual_retval": actual,
                "run": run_result.to_json(),
                "passed": actual == expected,
            }
            functional = report["functional"]
            assert isinstance(functional, list)
            functional.append(entry)

        report["passed"] = all(test["passed"] for test in report["functional"])
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1
    finally:
        cleanup_pin_tree(prog_dir)
        cleanup_pin_tree(map_dir)
        if work_dir_obj is not None:
            work_dir_obj.cleanup()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
