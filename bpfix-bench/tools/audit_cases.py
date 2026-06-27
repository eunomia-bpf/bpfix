#!/usr/bin/env python3
"""Audit bpfix-bench case structure and oracle coverage."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import run_suite


REQUIRED_FILES = {
    "README.md",
    "buggy.bpf.c",
    "verifier.log",
    "diagnostic.txt",
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


def literal_list_count(value: Any) -> int | None:
    return len(value) if isinstance(value, list) else None


def parse_test_tree(test_py: Path) -> ast.Module | None:
    try:
        return ast.parse(test_py.read_text(encoding="utf-8"), filename=str(test_py))
    except SyntaxError:
        return None


def run_case_keywords_from_tree(tree: ast.Module) -> dict[str, ast.AST] | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "run_case":
            return {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg is not None}
    return None


def module_literal_dict(tree: ast.Module, name: str) -> dict[str, Any] | None:
    for node in tree.body:
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            value = node.value
        if value is None:
            continue
        try:
            parsed = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def module_literal_list_count(tree: ast.Module, name: str) -> int | None:
    for node in tree.body:
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            value = node.value
        if value is None:
            continue
        try:
            parsed = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return None
        return literal_list_count(parsed)
    return None


def custom_oracle_coverage(tree: ast.Module) -> dict[str, int | None]:
    coverage = module_literal_dict(tree, "CUSTOM_ORACLE_COVERAGE") or {}
    expected_reject_substrings = literal_list_count(coverage.get("expected_reject_substrings"))
    if expected_reject_substrings is None:
        expected_reject_substrings = module_literal_list_count(tree, "EXPECTED_REJECT_SUBSTRINGS")
    return {
        "expected_reject_substrings": expected_reject_substrings,
        "functional_tests": literal_list_count(coverage.get("functional_tests")),
        "required_success_substrings": literal_list_count(coverage.get("required_success_substrings")),
        "required_success_predicates": literal_list_count(coverage.get("required_success_predicates")),
    }


def audit_diagnostic_text(case_dir: Path, errors: list[str]) -> dict[str, Any] | None:
    path = case_dir / "diagnostic.txt"
    text = path.read_text(encoding="utf-8")
    error = re.search(r"^error\[(BPFIX-E\d+)\]:", text, re.MULTILINE)
    failure_class = re.search(r"^\s+= class: ([^\n]+)$", text, re.MULTILINE)
    diagnostic = re.search(r"^\s+= diagnostic: ([^,\n]+)", text, re.MULTILINE)
    if error is None:
        errors.append("diagnostic.txt missing BPFix error header")
    if failure_class is None:
        errors.append("diagnostic.txt missing class line")
    if diagnostic is None:
        errors.append("diagnostic.txt missing diagnostic line")
    elif diagnostic.group(1) != "supported":
        errors.append(f"diagnostic.txt diagnostic is {diagnostic.group(1)!r}, expected supported")
    if "--> buggy.bpf.c:" not in text:
        errors.append("diagnostic.txt missing buggy.bpf.c source span")
    if "help:" not in text:
        errors.append("diagnostic.txt missing help text")
    if "required proof:" not in text:
        errors.append("diagnostic.txt missing required proof")
    if errors:
        return None
    return {
        "error_id": error.group(1),
        "failure_class": failure_class.group(1),
    }


def audit_test_py(
    case_dir: Path,
    errors: list[str],
    *,
    oracle_kind: list[str] | None = None,
) -> dict[str, int | None | bool]:
    tree = parse_test_tree(case_dir / "test.py")
    keywords = run_case_keywords_from_tree(tree) if tree is not None else None
    oracle_kind_set = set(oracle_kind or [])
    custom_oracle = bool(CUSTOM_ORACLE_KINDS & oracle_kind_set)
    bpftool_prog_run = oracle_kind is None or BPFTOOL_PROG_RUN_ORACLE in oracle_kind_set
    if keywords is None:
        coverage = custom_oracle_coverage(tree) if custom_oracle and tree is not None else {}
        if not custom_oracle:
            errors.append("test.py must either contain run_case(...) or declare a custom oracle kind")
        else:
            if not coverage.get("expected_reject_substrings"):
                errors.append("custom oracle must declare expected_reject_substrings coverage")
            if bpftool_prog_run and not coverage.get("functional_tests"):
                errors.append("custom oracle with bpftool_prog_run must declare functional_tests coverage")
        return {
            "expected_reject_substrings": coverage.get("expected_reject_substrings"),
            "functional_tests": coverage.get("functional_tests"),
            "required_success_substrings": coverage.get("required_success_substrings"),
            "required_success_predicates": coverage.get("required_success_predicates"),
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

    diagnostic = None
    test_summary: dict[str, int | None | bool] = {}
    if not missing:
        diagnostic = audit_diagnostic_text(case_dir, errors)
        test_summary = audit_test_py(case_dir, errors, oracle_kind=oracle_kind)
        audit_prompt(case_dir, errors)
        if "BEGIN PROG LOAD LOG" not in (case_dir / "verifier.log").read_text(encoding="utf-8"):
            errors.append("verifier.log does not contain BEGIN PROG LOAD LOG")

    smoke_report: dict[str, Any] | None = None
    if smoke and not missing:
        completed = run(
            [
                sys.executable,
                str(root / "bpfix-bench" / "tools" / "run_suite.py"),
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
        "error_id": diagnostic.get("error_id") if isinstance(diagnostic, dict) else None,
        "failure_class": diagnostic.get("failure_class") if isinstance(diagnostic, dict) else None,
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
