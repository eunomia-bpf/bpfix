#!/usr/bin/env python3
"""Audit bpfix-test split files and heldout contamination rules."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import audit_cases
import run_suite


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def infer_expected_count(path: Path) -> int | None:
    match = re.search(r"(\d+)", path.stem)
    return int(match.group(1)) if match else None


def duplicates(items: list[str]) -> list[str]:
    seen: set[str] = set()
    repeated: list[str] = []
    for item in items:
        if item in seen and item not in repeated:
            repeated.append(item)
        seen.add(item)
    return sorted(repeated)


def case_index(root: Path) -> dict[str, Path]:
    return {case.name: case for case in run_suite.discover_cases(root)}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", type=Path, required=True, help="Split file containing case ids.")
    parser.add_argument("--expected-count", type=int, help="Required number of cases.")
    parser.add_argument(
        "--disallow-overlap",
        type=Path,
        action="append",
        default=[],
        help="Reject case ids that also appear in this split.",
    )
    parser.add_argument("--audit-cases", action="store_true", help="Run structural case audit for split cases.")
    parser.add_argument("--smoke", action="store_true", help="Also run buggy-reject smoke for each split case.")
    return parser.parse_args(argv)


def audit_split(args: argparse.Namespace) -> dict[str, Any]:
    root = repo_root()
    case_ids = run_suite.read_split_file(args.split)
    expected_count = args.expected_count
    if expected_count is None:
        expected_count = infer_expected_count(args.split)

    known_cases = case_index(root)
    split_duplicates = duplicates(case_ids)
    missing_cases = sorted(set(case_ids) - set(known_cases))
    overlap: dict[str, list[str]] = {}
    for other_split in args.disallow_overlap:
        other_ids = set(run_suite.read_split_file(other_split))
        shared = sorted(set(case_ids) & other_ids)
        overlap[str(other_split)] = shared

    errors: list[str] = []
    if expected_count is not None and len(case_ids) != expected_count:
        errors.append(f"expected {expected_count} cases, found {len(case_ids)}")
    if split_duplicates:
        errors.append(f"duplicate case ids: {', '.join(split_duplicates)}")
    if missing_cases:
        errors.append(f"unknown case ids: {', '.join(missing_cases)}")
    for other_split, shared in overlap.items():
        if shared:
            errors.append(f"overlap with {other_split}: {', '.join(shared)}")

    case_reports: list[dict[str, Any]] = []
    if args.audit_cases and not missing_cases and not split_duplicates:
        for case_id in case_ids:
            report = audit_cases.audit_case(known_cases[case_id], smoke=args.smoke, root=root)
            case_reports.append(report)
        failed_cases = [report["case"] for report in case_reports if not report["passed"]]
        if failed_cases:
            errors.append(f"case audit failed: {', '.join(failed_cases)}")

    passed = not errors
    return {
        "passed": passed,
        "split": str(args.split),
        "expected_count": expected_count,
        "actual_count": len(case_ids),
        "duplicates": split_duplicates,
        "missing_cases": missing_cases,
        "overlap": overlap,
        "audit": {
            "enabled": bool(args.audit_cases),
            "smoke": bool(args.smoke),
            "total": len(case_reports),
            "passed": sum(1 for report in case_reports if report["passed"]),
            "failed": sum(1 for report in case_reports if not report["passed"]),
            "reports": case_reports,
        },
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    summary = audit_split(parse_args(argv))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
