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
import prompt_manifest


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


def selected_llm_identity(summary: dict[str, Any]) -> dict[str, Any] | None:
    config = selected_llm_config(summary)
    if config is None:
        return None
    return {
        "model": config.get("model"),
        "temperature": config.get("temperature"),
        "max_tokens": config.get("max_tokens"),
        "timeout_sec": config.get("timeout_sec"),
        "model_file_sha256": config.get("model_file_sha256"),
        "llama_cpp_commit": config.get("llama_cpp_commit"),
    }


def selected_toolchain_config(summary: dict[str, Any]) -> dict[str, Any] | None:
    metadata = run_metadata(summary)
    if metadata is None:
        return None
    toolchain = metadata.get("toolchain")
    return toolchain if isinstance(toolchain, dict) else None


def normalize_uname(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    parts = value.split()
    if len(parts) >= 3 and parts[0] == "Linux":
        return " ".join([parts[0], "<host>", *parts[2:]])
    return value


def selected_toolchain_identity(summary: dict[str, Any]) -> dict[str, Any] | None:
    toolchain = selected_toolchain_config(summary)
    if toolchain is None:
        return None
    return {
        "kernel": normalize_uname(toolchain.get("kernel")),
        "clang": toolchain.get("clang"),
        "bpftool": toolchain.get("bpftool"),
        "llvm_objdump": toolchain.get("llvm_objdump"),
    }


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


def expected_prompt_index(
    path: Path | None,
    expected_split: dict[str, Any] | None,
    *,
    allow_dirty_prompt_manifest: bool,
    allow_missing_prompt_manifest: bool,
) -> tuple[dict[tuple[str, str], dict[str, Any]] | None, str | None]:
    if path is None:
        if allow_missing_prompt_manifest:
            return None, None
        raise SystemExit("--prompt-manifest is required; use --allow-missing-prompt-manifest only for dev dry runs")
    manifest = prompt_manifest.read_manifest(path)
    if manifest.get("schema_version") != prompt_manifest.SCHEMA_VERSION:
        raise SystemExit(f"{path}: schema_version must be {prompt_manifest.SCHEMA_VERSION!r}")
    git = manifest.get("git")
    if isinstance(git, dict) and git.get("dirty") is True and not allow_dirty_prompt_manifest:
        raise SystemExit(f"{path}: manifest was generated from a dirty worktree")
    manifest_git_commit = git.get("commit") if isinstance(git, dict) and isinstance(git.get("commit"), str) else None
    if manifest_git_commit is None:
        raise SystemExit(f"{path}: git.commit is required")
    manifest_split = manifest.get("split")
    if not isinstance(manifest_split, dict):
        raise SystemExit(f"{path}: split must be an object")
    if expected_split is not None:
        for key in ["sha256", "case_count", "cases"]:
            if manifest_split.get(key) != expected_split[key]:
                raise SystemExit(f"{path}: split.{key} does not match --split")
    index = prompt_manifest.prompt_index(manifest)
    prompts = manifest.get("prompts")
    if not isinstance(prompts, list):
        raise SystemExit(f"{path}: prompts must be a list")
    if len(index) != len(prompts):
        raise SystemExit(f"{path}: prompts contains malformed or duplicate rows")
    return index, manifest_git_commit


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
    expected_prompts: dict[tuple[str, str], dict[str, Any]] | None,
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

        if isinstance(case_id, str) and isinstance(mode, str) and expected_prompts is not None:
            expected_prompt = expected_prompts.get((case_id, mode))
            if expected_prompt is None:
                errors.append(f"{path}: {case_id}: missing prompt manifest row for mode {mode}")
            else:
                for field in ["prompt_sha256", "prompt_chars", "source_chars", "diagnostic_chars"]:
                    if raw_result.get(field) != expected_prompt.get(field):
                        errors.append(
                            f"{path}: {case_id}: {field} {raw_result.get(field)!r} "
                            f"does not match prompt manifest {expected_prompt.get(field)!r}"
                        )

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
    parser.add_argument("--prompt-manifest", type=Path, help="Frozen prompt manifest to verify result hashes.")
    parser.add_argument(
        "--allow-missing-prompt-manifest",
        action="store_true",
        help="Allow result audits without a prompt manifest. Only for dev dry runs.",
    )
    parser.add_argument(
        "--allow-dirty-prompt-manifest",
        action="store_true",
        help="Allow a prompt manifest generated from a dirty worktree. Only for dev dry runs.",
    )
    parser.add_argument(
        "--allow-commit-drift",
        action="store_true",
        help="Allow result git commits to differ from the prompt manifest commit. Only for non-paper debugging.",
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
    expected_prompts, prompt_manifest_commit = expected_prompt_index(
        args.prompt_manifest,
        expected_split,
        allow_dirty_prompt_manifest=args.allow_dirty_prompt_manifest,
        allow_missing_prompt_manifest=args.allow_missing_prompt_manifest,
    )

    summaries: list[dict[str, Any]] = []
    mode_to_path: dict[str, str] = {}
    case_order: list[str] | None = None
    llm_config: dict[str, Any] | None = None
    llm_identity_config: dict[str, Any] | None = None
    toolchain_config: dict[str, Any] | None = None
    toolchain_identity_config: dict[str, Any] | None = None
    git_commit: str | None = None
    for path in args.summary:
        summary = read_summary(path)
        report, summary_errors = audit_one_summary(
            path=path,
            summary=summary,
            expected_count=expected_count,
            expected_split=expected_split,
            expected_prompts=expected_prompts,
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
        current_llm_identity = selected_llm_identity(summary)
        if current_llm is not None and llm_config is None:
            llm_config = current_llm
        if current_llm_identity is not None:
            if llm_config is None:
                llm_config = current_llm
            if llm_identity_config is None:
                llm_identity_config = current_llm_identity
            elif current_llm_identity != llm_identity_config:
                errors.append(f"{path}: LLM semantic configuration differs from the first summary")

        current_toolchain = selected_toolchain_config(summary)
        current_toolchain_identity = selected_toolchain_identity(summary)
        if current_toolchain is not None and toolchain_config is None:
            toolchain_config = current_toolchain
        if current_toolchain_identity is not None:
            if toolchain_config is None:
                toolchain_config = current_toolchain
            if toolchain_identity_config is None:
                toolchain_identity_config = current_toolchain_identity
            elif current_toolchain_identity != toolchain_identity_config:
                errors.append(f"{path}: toolchain semantic metadata differs from the first summary")

        current_git = selected_git_config(summary)
        if current_git is not None and isinstance(current_git.get("commit"), str):
            if (
                prompt_manifest_commit is not None
                and current_git["commit"] != prompt_manifest_commit
                and not args.allow_commit_drift
            ):
                errors.append(f"{path}: git commit differs from prompt manifest commit")
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
        "prompt_manifest_commit": prompt_manifest_commit,
        "llm_config": llm_config,
        "llm_identity_config": llm_identity_config,
        "toolchain_config": toolchain_config,
        "toolchain_identity_config": toolchain_identity_config,
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
