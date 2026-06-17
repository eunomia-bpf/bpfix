#!/usr/bin/env python3
"""Refresh raw verifier logs and BPFix structured diagnostics for bpfix-test."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def discover_cases(root: Path) -> list[Path]:
    cases_root = root / "bpfix-test" / "cases"
    return sorted(case for case in cases_root.iterdir() if (case / "buggy.bpf.c").exists())


def run(argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)


def refresh_case(case_dir: Path, bpfix_bin: Path) -> dict[str, object]:
    test_py = case_dir / "test.py"
    log_path = case_dir / "verifier.log"
    structured_path = case_dir / "structured.json"

    reject = run(
        [
            sys.executable,
            str(test_py),
            "--source",
            str(case_dir / "buggy.bpf.c"),
            "--expect-reject",
            "--save-log",
            str(log_path),
        ],
        cwd=repo_root(),
    )
    if reject.returncode != 0:
        return {
            "case": case_dir.name,
            "passed": False,
            "stage": "reject-capture",
            "stdout": reject.stdout,
            "stderr": reject.stderr,
        }

    structured = run(
        [str(bpfix_bin), "--format", "json", str(log_path)],
        cwd=repo_root(),
    )
    if structured.returncode != 0:
        return {
            "case": case_dir.name,
            "passed": False,
            "stage": "bpfix",
            "stdout": structured.stdout,
            "stderr": structured.stderr,
        }
    structured_path.write_text(structured.stdout, encoding="utf-8")
    return {"case": case_dir.name, "passed": True}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bpfix-bin", type=Path, default=repo_root() / "target" / "debug" / "bpfix")
    parser.add_argument("--case", action="append", help="Refresh only this case id.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = repo_root()
    bpfix_bin = args.bpfix_bin
    if not bpfix_bin.exists():
        build = run(["cargo", "build", "-p", "bpfix"], cwd=root)
        if build.returncode != 0:
            print(build.stdout, end="")
            print(build.stderr, end="", file=sys.stderr)
            return build.returncode

    wanted = set(args.case or [])
    reports = []
    for case_dir in discover_cases(root):
        if wanted and case_dir.name not in wanted:
            continue
        report = refresh_case(case_dir, bpfix_bin.resolve())
        reports.append(report)
        status = "ok" if report["passed"] else f"failed:{report['stage']}"
        print(f"{case_dir.name}: {status}")
        if not report["passed"]:
            print(report.get("stdout", ""), end="")
            print(report.get("stderr", ""), end="", file=sys.stderr)

    return 0 if reports and all(report["passed"] for report in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
