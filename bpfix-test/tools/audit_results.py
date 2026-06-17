#!/usr/bin/env python3
"""Audit bpfix-test LLM result summaries before benchmark reporting."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import run_suite


ALLOWED_STATUSES = {"pass", "fail", "model_error", "prompt_written"}
ALLOWED_FAILURE_STAGES = {
    "pass",
    "prompt_only",
    "model_call",
    "extract_source",
    "compile",
    "map_setup",
    "verifier_load",
    "functional_oracle",
    "auxiliary_proof_predicate",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def read_summary(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{path}: summary must be a JSON object")
    return payload


def split_cases(path: Path | None) -> list[str] | None:
    if path is None:
        return None
    return run_suite.read_split_file(path)


def result_cases(summary: dict[str, Any]) -> list[str]:
    cases: list[str] = []
    results = summary.get("results", [])
    if not isinstance(results, list):
        return cases
    for result in results:
        if isinstance(result, dict) and isinstance(result.get("case"), str):
            cases.append(result["case"])
    return cases


def split_record(summary: dict[str, Any]) -> dict[str, Any] | None:
    run_metadata = summary.get("run_metadata")
    if not isinstance(run_metadata, dict):
        return None
    case_selection = run_metadata.get("case_selection")
    if not isinstance(case_selection, dict):
        return None
    split = case_selection.get("split")
    return split if isinstance(split, dict) else None


def run_metadata(summary: dict[str, Any]) -> dict[str, Any] | None:
    metadata = summary.get("run_metadata")
    return metadata if isinstance(metadata, dict) else None


def selected_llm_config(summary: dict[str, Any]) -> dict[str, Any] | None:
    metadata = run_metadata(summary)
    if metadata is None:
        return None
    llm = metadata.get("llm")
    if not isinstance(llm, dict):
        return None
    model_file = llm.get("model_file")
    if not isinstance(model_file, dict):
        model_file = {}
    llama_cpp = llm.get("llama_cpp")
    if not isinstance(llama_cpp, dict):
        llama_cpp = {}
    return {
        "base_url": llm.get("base_url"),
        "model": llm.get("model"),
        "temperature": llm.get("temperature"),
        "max_tokens": llm.get("max_tokens"),
        "timeout_sec": llm.get("timeout_sec"),
        "model_file_path": model_file.get("path"),
        "model_file_sha256": model_file.get("sha256"),
        "llama_cpp_path": llama_cpp.get("path"),
        "llama_cpp_commit": llama_cpp.get("commit"),
    }


def selected_toolchain_config(summary: dict[str, Any]) -> dict[str, Any] | None:
    metadata = run_metadata(summary)
    if metadata is None:
        return None
    toolchain = metadata.get("toolchain")
    return toolchain if isinstance(toolchain, dict) else None


def selected_git_config(summary: dict[str, Any]) -> dict[str, Any] | None:
    metadata = run_metadata(summary)
    if metadata is None:
        return None
    git = metadata.get("git")
    return git if isinstance(git, dict) else None


def has_model_fingerprint(llm_config: dict[str, Any]) -> bool:
    sha256 = llm_config.get("model_file_sha256")
    if not isinstance(sha256, str):
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", sha256.strip()))


def expected_split_metadata(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    cases = run_suite.read_split_file(path)
    return {
        "path": str(resolved),
        "sha256": run_suite.sha256_file(resolved),
        "case_count": len(cases),
        "cases": cases,
    }


def stage_for_result(result: dict[str, Any]) -> str | None:
    stage = result.get("failure_stage")
    if isinstance(stage, str):
        return stage
    status = result.get("status")
    if status == "pass":
        return "pass"
    if status == "prompt_written":
        return "prompt_only"
    return None


def audit_one_summary(
    *,
    path: Path,
    summary: dict[str, Any],
    expected_count: int | None,
    expected_split: dict[str, Any] | None,
    allow_prompt_only: bool,
    allow_dirty: bool,
    allow_missing_model_digest: bool,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    mode = summary.get("mode")
    if mode not in run_suite.MODES:
        errors.append(f"{path}: mode must be one of {run_suite.MODES}, got {mode!r}")

    results = summary.get("results")
    if not isinstance(results, list):
        errors.append(f"{path}: results must be a list")
        results = []

    total = summary.get("total")
    if total != len(results):
        errors.append(f"{path}: total {total!r} does not match {len(results)} result rows")
    if expected_count is not None and len(results) != expected_count:
        errors.append(f"{path}: expected {expected_count} cases, found {len(results)} result rows")

    passed = summary.get("passed")
    actual_passed = sum(1 for result in results if isinstance(result, dict) and result.get("status") == "pass")
    if passed != actual_passed:
        errors.append(f"{path}: passed {passed!r} does not match {actual_passed} pass rows")

    metadata = run_metadata(summary)
    if metadata is None:
        errors.append(f"{path}: run_metadata is required")
    else:
        git = selected_git_config(summary)
        if git is None:
            errors.append(f"{path}: run_metadata.git is required")
        else:
            if not isinstance(git.get("commit"), str) or not git.get("commit"):
                errors.append(f"{path}: run_metadata.git.commit is required")
            if git.get("dirty") is True and not allow_dirty:
                errors.append(f"{path}: dirty git worktree cannot be reported without --allow-dirty")
            elif not isinstance(git.get("dirty"), bool):
                errors.append(f"{path}: run_metadata.git.dirty must be boolean")
        llm_config = selected_llm_config(summary)
        if llm_config is None:
            errors.append(f"{path}: run_metadata.llm is required")
        elif not allow_missing_model_digest and not has_model_fingerprint(llm_config):
            errors.append(
                f"{path}: 64-hex SHA-256 model digest is required; pass --model-sha256 or "
                "use --allow-missing-model-digest only for non-paper dry runs"
            )
        if selected_toolchain_config(summary) is None:
            errors.append(f"{path}: run_metadata.toolchain is required")

    cases: list[str] = []
    duplicate_cases: list[str] = []
    seen_cases: set[str] = set()
    status_counts: Counter[str] = Counter()
    stage_counts: Counter[str] = Counter()
    for index, raw_result in enumerate(results):
        if not isinstance(raw_result, dict):
            errors.append(f"{path}: results[{index}] must be an object")
            continue
        case_id = raw_result.get("case")
        if not isinstance(case_id, str):
            errors.append(f"{path}: results[{index}].case must be a string")
        else:
            cases.append(case_id)
            if case_id in seen_cases and case_id not in duplicate_cases:
                duplicate_cases.append(case_id)
            seen_cases.add(case_id)

        status = raw_result.get("status")
        if status not in ALLOWED_STATUSES:
            errors.append(f"{path}: {case_id or f'results[{index}]'} has invalid status {status!r}")
            continue
        status_counts[str(status)] += 1

        if status == "prompt_written" and not allow_prompt_only:
            errors.append(f"{path}: {case_id}: prompt-only row cannot be reported as benchmark result")

        result_mode = raw_result.get("mode")
        if status != "prompt_written" and result_mode != mode:
            errors.append(f"{path}: {case_id}: result.mode {result_mode!r} does not match summary mode {mode!r}")

        stage = stage_for_result(raw_result)
        if stage is None:
            errors.append(f"{path}: {case_id}: missing failure_stage")
        elif stage not in ALLOWED_FAILURE_STAGES:
            errors.append(f"{path}: {case_id}: invalid failure_stage {stage!r}")
        else:
            stage_counts[stage] += 1
            if status == "pass" and stage != "pass":
                errors.append(f"{path}: {case_id}: pass row must use failure_stage 'pass'")
            if status == "fail" and stage in {"pass", "prompt_only", "model_call", "extract_source"}:
                errors.append(f"{path}: {case_id}: fail row has incompatible failure_stage {stage!r}")
            if status == "model_error" and stage not in {"model_call", "extract_source"}:
                errors.append(f"{path}: {case_id}: model_error row has incompatible failure_stage {stage!r}")

    if duplicate_cases:
        errors.append(f"{path}: duplicate result case ids: {', '.join(sorted(duplicate_cases))}")

    split = split_record(summary)
    split_summary: dict[str, Any] = {"present": split is not None}
    if expected_split is not None:
        if split is None:
            errors.append(f"{path}: run_metadata.case_selection.split is required")
        else:
            for key in ["sha256", "case_count"]:
                if split.get(key) != expected_split[key]:
                    errors.append(
                        f"{path}: split {key} {split.get(key)!r} does not match "
                        f"{expected_split[key]!r}"
                    )
            if cases != expected_split["cases"]:
                errors.append(f"{path}: result case order does not match split file")
    if split is not None:
        split_summary.update(
            {
                "path": split.get("path"),
                "sha256": split.get("sha256"),
                "case_count": split.get("case_count"),
                "expected_count": split.get("expected_count"),
            }
        )

    return (
        {
            "path": str(path),
            "mode": mode,
            "total": len(results),
            "passed": actual_passed,
            "cases": cases,
            "status_counts": dict(sorted(status_counts.items())),
            "failure_stage_counts": dict(sorted(stage_counts.items())),
            "split": split_summary,
        },
        errors,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path, nargs="+", help="run_suite.py summary.json files.")
    parser.add_argument("--split", type=Path, help="Expected split file for all summaries.")
    parser.add_argument("--expected-count", type=int, help="Expected number of cases per summary.")
    parser.add_argument(
        "--required-mode",
        action="append",
        choices=run_suite.MODES,
        default=[],
        help="Require one summary for this prompt mode. Repeat for a matrix.",
    )
    parser.add_argument(
        "--allow-prompt-only",
        action="store_true",
        help="Allow prompt_written rows. This is only for dry-run prompt audits, not benchmark reporting.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow summaries produced from a dirty git worktree. Not valid for paper-grade clean reporting.",
    )
    parser.add_argument(
        "--allow-missing-model-digest",
        action="store_true",
        help="Allow missing model_file.sha256. This is only for dev or cloud dry runs, not paper-grade clean reporting.",
    )
    parser.add_argument(
        "--no-require-same-cases",
        action="store_true",
        help="Do not require every summary to contain the same ordered case list.",
    )
    return parser.parse_args(argv)


def audit_results(args: argparse.Namespace) -> dict[str, Any]:
    errors: list[str] = []
    expected_split = expected_split_metadata(args.split) if args.split is not None else None
    expected_count = args.expected_count
    if expected_count is None and expected_split is not None:
        expected_count = int(expected_split["case_count"])

    summaries: list[dict[str, Any]] = []
    mode_to_path: dict[str, str] = {}
    case_order: list[str] | None = None
    llm_config: dict[str, Any] | None = None
    toolchain_config: dict[str, Any] | None = None
    git_commit: str | None = None
    for path in args.summary:
        summary = read_summary(path)
        report, summary_errors = audit_one_summary(
            path=path,
            summary=summary,
            expected_count=expected_count,
            expected_split=expected_split,
            allow_prompt_only=args.allow_prompt_only,
            allow_dirty=args.allow_dirty,
            allow_missing_model_digest=args.allow_missing_model_digest,
        )
        summaries.append(report)
        errors.extend(summary_errors)

        mode = report.get("mode")
        if isinstance(mode, str):
            if mode in mode_to_path:
                errors.append(f"duplicate mode {mode!r}: {mode_to_path[mode]} and {path}")
            mode_to_path[mode] = str(path)

        cases = report.get("cases")
        if isinstance(cases, list):
            if case_order is None:
                case_order = [case for case in cases if isinstance(case, str)]
            elif not args.no_require_same_cases and case_order != cases:
                errors.append(f"{path}: case list differs from the first summary")

        current_llm = selected_llm_config(summary)
        if current_llm is not None:
            if llm_config is None:
                llm_config = current_llm
            elif current_llm != llm_config:
                errors.append(f"{path}: LLM configuration differs from the first summary")

        current_toolchain = selected_toolchain_config(summary)
        if current_toolchain is not None:
            if toolchain_config is None:
                toolchain_config = current_toolchain
            elif current_toolchain != toolchain_config:
                errors.append(f"{path}: toolchain metadata differs from the first summary")

        current_git = selected_git_config(summary)
        if current_git is not None and isinstance(current_git.get("commit"), str):
            if git_commit is None:
                git_commit = current_git["commit"]
            elif current_git["commit"] != git_commit:
                errors.append(f"{path}: git commit differs from the first summary")

    required_modes = args.required_mode
    missing_modes = [mode for mode in required_modes if mode not in mode_to_path]
    if missing_modes:
        errors.append(f"missing required mode(s): {', '.join(missing_modes)}")

    paired_results: list[dict[str, Any]] = []
    if case_order is not None:
        raw_summaries = [(read_summary(path), path) for path in args.summary]
        for case_id in case_order:
            row: dict[str, Any] = {"case": case_id}
            for summary, _path in raw_summaries:
                mode = summary.get("mode")
                results = summary.get("results", [])
                if not isinstance(mode, str) or not isinstance(results, list):
                    continue
                match = next(
                    (
                        result
                        for result in results
                        if isinstance(result, dict) and result.get("case") == case_id
                    ),
                    None,
                )
                if match is not None:
                    row[mode] = {
                        "status": match.get("status"),
                        "failure_stage": stage_for_result(match),
                    }
            paired_results.append(row)

    return {
        "passed": not errors,
        "expected_count": expected_count,
        "required_modes": required_modes,
        "modes": sorted(mode_to_path),
        "git_commit": git_commit,
        "llm_config": llm_config,
        "toolchain_config": toolchain_config,
        "summaries": summaries,
        "paired_results": paired_results,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    summary = audit_results(parse_args(argv))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
