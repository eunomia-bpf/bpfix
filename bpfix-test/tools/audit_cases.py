#!/usr/bin/env python3
"""Audit bpfix-test case structure and oracle coverage."""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import run_suite


REQUIRED_FILES = {
    "README.md",
    "buggy.bpf.c",
    "verifier.log",
    "structured.json",
    "test.py",
}

FORBIDDEN_PROMPT_SNIPPETS = [
    "functional_tests",
    "expected_retval",
    "run_case(",
    "success_log_checks",
]
CUSTOM_ORACLE_KINDS = {"attach_or_runtime", "environment_config", "custom_oracle"}
BPFTOOL_PROG_RUN_ORACLE = "bpftool_prog_run"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{path}: manifest must be a JSON object")
    return payload


def manifest_case_oracle_kinds(path: Path | None) -> dict[str, list[str]]:
    if path is None:
        return {}
    manifest = read_manifest(path)
    defaults = manifest.get("case_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        raise SystemExit(f"{path}: manifest.cases must be a list")
    values: dict[str, list[str]] = {}
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            continue
        case = {**defaults, **raw_case}
        case_id = case.get("case_id")
        oracle_kind = case.get("oracle_kind")
        if isinstance(case_id, str) and isinstance(oracle_kind, list):
            values[case_id] = [kind for kind in oracle_kind if isinstance(kind, str)]
    return values


def discover_cases(root: Path) -> list[Path]:
    return run_suite.discover_cases(root)


def run(argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)


def list_len(value: ast.AST | None) -> int | None:
    if isinstance(value, ast.List | ast.Tuple):
        return len(value.elts)
    return None


def run_case_keywords(test_py: Path) -> dict[str, ast.AST] | None:
    try:
        tree = ast.parse(test_py.read_text(encoding="utf-8"), filename=str(test_py))
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "run_case":
            return {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg is not None}
    return None


def audit_structured_json(case_dir: Path, errors: list[str], warnings: list[str]) -> dict[str, Any] | None:
    path = case_dir / "structured.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"structured.json is not valid JSON: {exc}")
        return None

    for field in ["diagnostic_version", "error_id", "failure_class", "diagnostic_kind", "required_proof"]:
        if not payload.get(field):
            errors.append(f"structured.json missing {field}")
    if payload.get("diagnostic_kind") != "supported":
        errors.append(f"structured.json diagnostic_kind is {payload.get('diagnostic_kind')!r}, expected supported")

    source_span = payload.get("source_span")
    if not isinstance(source_span, dict):
        errors.append("structured.json missing source_span object")
    else:
        if source_span.get("path") != "buggy.bpf.c":
            errors.append(f"source_span.path is {source_span.get('path')!r}, expected 'buggy.bpf.c'")
        if not isinstance(source_span.get("line_start"), int):
            errors.append("source_span.line_start is missing or not an integer")

    for field in ["help", "evidence"]:
        value = payload.get(field)
        if not isinstance(value, list) or not value:
            errors.append(f"structured.json {field} must be a non-empty list")

    if payload.get("diagnostic_version") != "bpfix.diagnostic/v3":
        warnings.append(f"diagnostic_version is {payload.get('diagnostic_version')!r}")
    return payload


def audit_test_py(
    case_dir: Path,
    errors: list[str],
    *,
    oracle_kind: list[str] | None = None,
) -> dict[str, int | None | bool]:
    keywords = run_case_keywords(case_dir / "test.py")
    oracle_kind_set = set(oracle_kind or [])
    custom_oracle = bool(CUSTOM_ORACLE_KINDS & oracle_kind_set)
    bpftool_prog_run = oracle_kind is None or BPFTOOL_PROG_RUN_ORACLE in oracle_kind_set
    if keywords is None:
        if bpftool_prog_run:
            errors.append("test.py does not contain a parseable run_case(...) call")
        elif not custom_oracle:
            errors.append("test.py must either contain run_case(...) or declare a custom oracle kind")
        return {
            "expected_reject_substrings": None,
            "functional_tests": None,
            "required_success_substrings": None,
            "required_success_predicates": None,
            "custom_oracle": custom_oracle,
            "bpftool_prog_run": bpftool_prog_run,
        }

    reject_count = list_len(keywords.get("expected_reject_substrings"))
    functional_count = list_len(keywords.get("functional_tests"))
    success_substring_count = list_len(keywords.get("required_success_substrings"))
    success_predicate_count = list_len(keywords.get("required_success_predicates"))

    if not reject_count:
        errors.append("expected_reject_substrings must be a non-empty literal list")
    if bpftool_prog_run and not functional_count:
        errors.append("functional_tests must be a non-empty literal list")

    return {
        "expected_reject_substrings": reject_count,
        "functional_tests": functional_count,
        "required_success_substrings": success_substring_count,
        "required_success_predicates": success_predicate_count,
        "custom_oracle": custom_oracle,
        "bpftool_prog_run": bpftool_prog_run,
    }


def audit_prompt(case_dir: Path, errors: list[str]) -> None:
    for mode in run_suite.MODES:
        prompt = run_suite.build_prompt(case_dir, mode)
        if case_dir.name in prompt:
            errors.append(f"{mode} prompt leaks semantic case id {case_dir.name!r}")
        for snippet in FORBIDDEN_PROMPT_SNIPPETS:
            if snippet in prompt:
                errors.append(f"{mode} prompt leaks oracle/test.py snippet {snippet!r}")
        if "reference fix" in prompt.lower() or "candidate.bpf.c" in prompt:
            errors.append(f"{mode} prompt appears to leak repair artifact wording")


def audit_case(
    case_dir: Path,
    *,
    smoke: bool,
    root: Path,
    oracle_kind: list[str] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    file_names = {path.name for path in case_dir.iterdir() if path.is_file()}
    missing = sorted(REQUIRED_FILES - file_names)
    extra = sorted(file_names - REQUIRED_FILES)
    if missing:
        errors.append(f"missing required files: {', '.join(missing)}")
    if extra:
        warnings.append(f"extra files: {', '.join(extra)}")

    structured = None
    test_summary: dict[str, int | None | bool] = {}
    if not missing:
        structured = audit_structured_json(case_dir, errors, warnings)
        test_summary = audit_test_py(case_dir, errors, oracle_kind=oracle_kind)
        audit_prompt(case_dir, errors)
        if "BEGIN PROG LOAD LOG" not in (case_dir / "verifier.log").read_text(encoding="utf-8"):
            errors.append("verifier.log does not contain BEGIN PROG LOAD LOG")

    smoke_report: dict[str, Any] | None = None
    if smoke and not missing:
        completed = run(
            [
                sys.executable,
                str(root / "bpfix-test" / "tools" / "run_suite.py"),
                "--smoke",
                "--case",
                case_dir.name,
            ],
            cwd=root,
        )
        smoke_report = {
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
        }
        if completed.returncode != 0:
            errors.append("smoke oracle failed")

    return {
        "case": case_dir.name,
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
        "error_id": structured.get("error_id") if isinstance(structured, dict) else None,
        "failure_class": structured.get("failure_class") if isinstance(structured, dict) else None,
        "test": test_summary,
        "smoke": smoke_report,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", help="Audit only this case id.")
    parser.add_argument("--split", type=Path, help="Audit case ids listed in this split file.")
    parser.add_argument("--manifest", type=Path, help="Manifest used to provide per-case oracle_kind context.")
    parser.add_argument("--smoke", action="store_true", help="Also run each case's buggy-reject smoke oracle.")
    return parser.parse_args(argv)


def select_cases(root: Path, wanted: list[str] | None) -> list[Path]:
    cases = discover_cases(root)
    if not wanted:
        return cases
    wanted_set = set(wanted)
    selected = [case for case in cases if case.name in wanted_set]
    missing = wanted_set - {case.name for case in selected}
    if missing:
        raise SystemExit(f"unknown case(s): {', '.join(sorted(missing))}")
    return selected


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.split is not None and args.case:
        raise SystemExit("--split and --case cannot be combined")
    root = repo_root()
    wanted = run_suite.read_split_file(args.split) if args.split is not None else args.case
    oracle_kinds = manifest_case_oracle_kinds(args.manifest)
    reports = [
        audit_case(
            case,
            smoke=args.smoke,
            root=root,
            oracle_kind=oracle_kinds.get(case.name),
        )
        for case in select_cases(root, wanted)
    ]
    summary = {
        "total": len(reports),
        "passed": sum(1 for report in reports if report["passed"]),
        "failed": sum(1 for report in reports if not report["passed"]),
        "reports": reports,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
