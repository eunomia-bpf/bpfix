#!/usr/bin/env python3
"""Generate or verify frozen bpfix-bench prompt manifests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import run_suite


SCHEMA_VERSION = "bpfix.test.prompt-manifest/v1"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def selected_modes(args: argparse.Namespace) -> list[str]:
    modes = args.mode or list(run_suite.MODES)
    duplicates = sorted({mode for mode in modes if modes.count(mode) > 1})
    if duplicates:
        raise SystemExit("duplicate mode(s): " + ", ".join(duplicates))
    return modes


def split_metadata(split: Path) -> dict[str, Any]:
    case_ids = run_suite.read_split_file(split)
    return {
        "path": str(split.resolve()),
        "sha256": run_suite.sha256_file(split.resolve()),
        "case_count": len(case_ids),
        "cases": case_ids,
    }


def prompt_record(case_dir: Path, mode: str) -> dict[str, Any]:
    prompt = run_suite.build_prompt(case_dir, mode)
    return {
        "case": case_dir.name,
        "mode": mode,
        "prompt_sha256": run_suite.sha256_text(prompt),
        "prompt_chars": len(prompt),
        "source_chars": len((case_dir / "buggy.bpf.c").read_text(encoding="utf-8")),
        "diagnostic_chars": len(run_suite.diagnostic_input(case_dir, mode)[1]),
    }


def build_manifest(split: Path, expected_count: int | None, modes: list[str]) -> dict[str, Any]:
    root = repo_root()
    split_meta = split_metadata(split)
    if expected_count is not None and split_meta["case_count"] != expected_count:
        raise SystemExit(f"{split}: expected {expected_count} cases, found {split_meta['case_count']}")
    case_dirs = run_suite.select_cases(root, split_meta["cases"])
    return {
        "schema_version": SCHEMA_VERSION,
        "split": split_meta,
        "modes": modes,
        "git": run_suite.git_metadata(root),
        "prompts": [
            prompt_record(case_dir, mode)
            for case_dir in case_dirs
            for mode in modes
        ],
    }


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{path}: manifest must be a JSON object")
    return payload


def prompt_index(manifest: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    prompts = manifest.get("prompts")
    if not isinstance(prompts, list):
        return {}
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for row in prompts:
        if not isinstance(row, dict):
            continue
        case_id = row.get("case")
        mode = row.get("mode")
        if isinstance(case_id, str) and isinstance(mode, str):
            index[(case_id, mode)] = row
    return index


def verify_manifest(
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    split: Path,
    expected_count: int | None,
    modes: list[str],
    allow_dirty_manifest: bool,
) -> dict[str, Any]:
    current = build_manifest(split, expected_count, modes)
    errors: list[str] = []
    warnings: list[str] = []

    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION!r}")

    manifest_split = manifest.get("split")
    if not isinstance(manifest_split, dict):
        errors.append("split must be an object")
        manifest_split = {}
    for key in ["sha256", "case_count", "cases"]:
        if manifest_split.get(key) != current["split"][key]:
            errors.append(f"split.{key} does not match current split")

    manifest_modes = manifest.get("modes")
    if manifest_modes != modes:
        errors.append("modes do not match requested modes")

    expected_rows = prompt_index(current)
    prompt_rows = manifest.get("prompts")
    if not isinstance(prompt_rows, list):
        errors.append("prompts must be a list")
        prompt_rows = []
    observed_rows = prompt_index(manifest)
    if len(observed_rows) != len(prompt_rows):
        errors.append("prompts contains malformed or duplicate rows")

    missing = sorted(set(expected_rows) - set(observed_rows))
    extra = sorted(set(observed_rows) - set(expected_rows))
    if missing:
        errors.append("missing prompt rows: " + ", ".join(f"{case}/{mode}" for case, mode in missing))
    if extra:
        errors.append("extra prompt rows: " + ", ".join(f"{case}/{mode}" for case, mode in extra))

    mismatches: list[str] = []
    for key in sorted(set(expected_rows) & set(observed_rows)):
        expected = expected_rows[key]
        observed = observed_rows[key]
        for field in ["prompt_sha256", "prompt_chars", "source_chars", "diagnostic_chars"]:
            if observed.get(field) != expected[field]:
                mismatches.append(f"{key[0]}/{key[1]}:{field}")
    if mismatches:
        errors.append("prompt manifest differs from current prompts: " + ", ".join(mismatches))

    git = manifest.get("git")
    if not isinstance(git, dict):
        errors.append("git must be an object")
    else:
        if not isinstance(git.get("commit"), str) or not git["commit"].strip():
            errors.append("git.commit is required")
        if git.get("dirty") is not False:
            message = "manifest was not generated from a clean worktree"
            if allow_dirty_manifest:
                warnings.append(message)
            else:
                errors.append(message)

    current_git = current.get("git")
    if isinstance(current_git, dict) and current_git.get("dirty") is True:
        message = "current worktree is dirty during prompt manifest verification"
        if allow_dirty_manifest:
            warnings.append(message)
        else:
            errors.append(message)

    return {
        "passed": not errors,
        "manifest": str(manifest_path),
        "split": str(split),
        "modes": modes,
        "prompt_count": len(observed_rows),
        "expected_prompt_count": len(expected_rows),
        "warnings": warnings,
        "errors": errors,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", type=Path, required=True, help="Split file containing case ids.")
    parser.add_argument("--expected-count", type=int, help="Required number of cases.")
    parser.add_argument("--mode", action="append", choices=run_suite.MODES, help="Prompt mode to include.")
    parser.add_argument("--output", type=Path, help="Write a generated manifest to this file.")
    parser.add_argument("--verify", type=Path, help="Verify an existing prompt manifest.")
    parser.add_argument(
        "--allow-dirty-manifest",
        action="store_true",
        help=(
            "Allow a manifest generated from, or verified against, a dirty worktree. "
            "Not valid for paper-grade clean reporting."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    modes = selected_modes(args)
    if args.output is not None and args.verify is not None:
        raise SystemExit("--output and --verify cannot be combined")
    if args.verify is not None:
        report = verify_manifest(
            manifest=read_manifest(args.verify),
            manifest_path=args.verify,
            split=args.split,
            expected_count=args.expected_count,
            modes=modes,
            allow_dirty_manifest=args.allow_dirty_manifest,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1

    manifest = build_manifest(args.split, args.expected_count, modes)
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(text, encoding="utf-8")
        print(
            json.dumps(
                {
                    "written": str(args.output),
                    "split": str(args.split),
                    "modes": modes,
                    "prompt_count": len(manifest["prompts"]),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
