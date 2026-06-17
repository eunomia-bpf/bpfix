#!/usr/bin/env python3
"""Shared oracle helpers for bpfix-test cases."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return self.stdout + self.stderr

    def to_json(self) -> dict[str, object]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def run(argv: list[str], *, timeout: int = 30) -> CommandResult:
    completed = subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return CommandResult(argv, completed.returncode, completed.stdout, completed.stderr)


def split_tool(env_name: str, default: str) -> list[str]:
    return shlex.split(os.environ.get(env_name, default))


def compile_bpf(source: Path, obj: Path) -> CommandResult:
    clang = split_tool("CLANG", "clang")
    argv = [
        *clang,
        "-target",
        "bpf",
        "-O2",
        "-g",
        "-I",
        "/usr/include",
        "-D__TARGET_ARCH_x86",
        "-c",
        str(source),
        "-o",
        str(obj),
    ]
    return run(argv)


def load_bpf(obj: Path, pin: Path, *, debug: bool = True) -> CommandResult:
    bpftool = split_tool("BPFTOOL", "sudo bpftool")
    argv = [*bpftool]
    if debug:
        argv.append("-d")
    argv.extend(["prog", "load", str(obj), str(pin), "type", "xdp"])
    return run(argv)


def run_pinned(pin: Path, data: bytes) -> tuple[int, CommandResult]:
    with tempfile.NamedTemporaryFile(prefix="bpfix-test-packet-", delete=False) as packet:
        packet.write(data)
        packet_path = Path(packet.name)
    try:
        bpftool = split_tool("BPFTOOL", "sudo bpftool")
        result = run(
            [
                *bpftool,
                "-j",
                "prog",
                "run",
                "pinned",
                str(pin),
                "data_in",
                str(packet_path),
                "repeat",
                "1",
            ]
        )
        if result.returncode != 0:
            return -1, result
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return -1, result
        return int(payload.get("retval", -1)), result
    finally:
        packet_path.unlink(missing_ok=True)


def cleanup_pin(pin: Path) -> None:
    run([*split_tool("PIN_RM", "sudo rm -f"), str(pin)], timeout=10)


def pin_name_for(source: Path) -> str:
    safe_stem = re.sub(r"[^A-Za-z0-9_]+", "_", source.stem).strip("_")
    if not safe_stem:
        safe_stem = "candidate"
    return f"bpfix_test_{safe_stem}_{os.getpid()}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a bpfix-test case oracle.")
    parser.add_argument("--source", type=Path, required=True, help="Candidate BPF C source.")
    parser.add_argument("--work-dir", type=Path, help="Directory for temporary build artifacts.")
    parser.add_argument(
        "--expect-reject",
        action="store_true",
        help="Pass only if the source is rejected by the verifier.",
    )
    parser.add_argument("--save-log", type=Path, help="Write verifier load output to this file.")
    return parser.parse_args(argv)


def normalize_load_output(output: str, *, source: Path, work_dir: Path, obj: Path, pin: Path) -> str:
    normalized = output
    replacements = {
        str(source): "buggy.bpf.c",
        str(work_dir): "<work-dir>",
        str(obj): "<object>",
        str(pin): "<bpffs-pin>",
    }
    for old, new in replacements.items():
        normalized = normalized.replace(old, new)
    normalized = re.sub(r"/tmp/bpfix-test-[A-Za-z0-9_.-]+", "<work-dir>", normalized)
    normalized = re.sub(r"0xffff[0-9a-fA-F]+", "0xffff000000000000", normalized)
    normalized = re.sub(r"fd=\d+", "fd=0", normalized)
    normalized = re.sub(r"verification time \d+ usec", "verification time 0 usec", normalized)
    return normalized


def evaluate_success_log_checks(
    load_result: CommandResult,
    required_success_substrings: list[str],
    required_success_predicates: list[tuple[str, Callable[[str], bool]]],
) -> list[dict[str, object]]:
    output = load_result.output
    checks: list[dict[str, object]] = [
        {
            "kind": "substring",
            "name": needle,
            "passed": needle in output,
        }
        for needle in required_success_substrings
    ]
    for name, predicate in required_success_predicates:
        try:
            passed = predicate(output)
            error = None
        except Exception as exc:  # pragma: no cover - defensive oracle reporting
            passed = False
            error = str(exc)
        check: dict[str, object] = {
            "kind": "predicate",
            "name": name,
            "passed": bool(passed),
        }
        if error is not None:
            check["error"] = error
        checks.append(check)
    return checks


def run_case(
    *,
    argv: list[str] | None,
    expected_reject_substrings: list[str],
    functional_tests: list[tuple[str, Callable[[], bytes], int]],
    required_success_substrings: list[str] | None = None,
    required_success_predicates: list[tuple[str, Callable[[str], bool]]] | None = None,
) -> int:
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

        load_result = load_bpf(obj, pin)
        report["load"] = load_result.to_json()
        if args.save_log is not None:
            args.save_log.write_text(
                normalize_load_output(load_result.output, source=source, work_dir=work_dir, obj=obj, pin=pin),
                encoding="utf-8",
            )

        if args.expect_reject:
            output = load_result.output
            rejected = load_result.returncode != 0 and all(
                needle in output for needle in expected_reject_substrings
            )
            report["passed"] = rejected
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if rejected else 1

        if load_result.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        required = required_success_substrings or []
        predicates = required_success_predicates or []
        checks = evaluate_success_log_checks(load_result, required, predicates)
        report["success_log_checks"] = checks
        if not all(check["passed"] for check in checks):
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        functional_results: list[dict[str, object]] = []
        ok = True
        for name, packet_fn, expected_retval in functional_tests:
            retval, prog_run = run_pinned(pin, packet_fn())
            passed = retval == expected_retval
            functional_results.append(
                {
                    "name": name,
                    "expected_retval": expected_retval,
                    "actual_retval": retval,
                    "passed": passed,
                    "run": prog_run.to_json(),
                }
            )
            ok = ok and passed
        report["functional"] = functional_results
        report["passed"] = ok
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if ok else 1
    finally:
        cleanup_pin(pin)
        if work_dir_obj is not None:
            work_dir_obj.cleanup()


if __name__ == "__main__":
    print("Import this module from a case test.py.", file=sys.stderr)
    raise SystemExit(2)
