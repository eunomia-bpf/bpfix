#!/usr/bin/env python3
"""Audit bpfix-test split files and heldout contamination rules."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import audit_cases
import run_suite


SCHEMA_VERSION = "bpfix.test.split-manifest/v1"
BUCKETS = {
    "proof_lifecycle",
    "source_object_correlation",
    "modern_bpf_protocol",
    "helper_memory_contract",
    "environment_config_boundary",
}
SOURCE_CATEGORIES = {
    "dev_calibration",
    "production_shaped_synthetic",
    "real_project_seed",
    "minimized_upstream_style",
}
PROG_TYPES = {"xdp", "tc", "tracepoint", "lsm", "cgroup", "perf_event", "socket_filter", "other"}
ORACLE_KINDS = {"compile", "verifier_load", "bpftool_prog_run", "helper_state", "proof_predicate"}
CLEAN60_BUCKET_TARGETS = {
    "proof_lifecycle": 18,
    "source_object_correlation": 12,
    "modern_bpf_protocol": 15,
    "helper_memory_contract": 8,
    "environment_config_boundary": 7,
}


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


def case_digest(case_dir: Path) -> str:
    digest = hashlib.sha256()
    for name in sorted(audit_cases.REQUIRED_FILES):
        path = case_dir / name
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def case_fingerprints(case_ids: list[str], known_cases: dict[str, Path]) -> dict[str, dict[str, str]]:
    fingerprints: dict[str, dict[str, str]] = {}
    for case_id in case_ids:
        case_dir = known_cases.get(case_id)
        if case_dir is None:
            continue
        fingerprints[case_id] = {
            "case_sha256": case_digest(case_dir),
            "buggy_source_sha256": file_digest(case_dir / "buggy.bpf.c"),
        }
    return fingerprints


def overlapping_fingerprints(
    current_ids: list[str],
    other_ids: list[str],
    known_cases: dict[str, Path],
) -> dict[str, list[dict[str, str]]]:
    current = case_fingerprints(current_ids, known_cases)
    other = case_fingerprints(other_ids, known_cases)
    overlaps: dict[str, list[dict[str, str]]] = {
        "case_sha256": [],
        "buggy_source_sha256": [],
    }
    for fingerprint_name in overlaps:
        other_by_hash = {
            values[fingerprint_name]: case_id
            for case_id, values in other.items()
            if fingerprint_name in values
        }
        for case_id, values in current.items():
            digest = values.get(fingerprint_name)
            other_case = other_by_hash.get(digest)
            if digest and other_case:
                overlaps[fingerprint_name].append(
                    {
                        "case": case_id,
                        "overlaps_case": other_case,
                        "sha256": digest,
                    }
                )
    return {name: matches for name, matches in overlaps.items() if matches}


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{path}: manifest must be a JSON object")
    return payload


def require_bool(value: Any) -> bool:
    return isinstance(value, bool)


def audit_manifest(
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    case_ids: list[str],
    known_cases: dict[str, Path],
    profile: str,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    defaults = manifest.get("case_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
        errors.append("manifest.case_defaults must be an object when present")

    cases = manifest.get("cases")
    if not isinstance(cases, list):
        cases = []
        errors.append("manifest.cases must be a list")

    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"manifest.schema_version must be {SCHEMA_VERSION!r}")
    expected_profile = "clean_heldout" if profile == "clean60" else "dev_calibration"
    if manifest.get("profile") != expected_profile:
        errors.append(f"manifest.profile must be {expected_profile!r}")

    manifest_ids = [case.get("case_id") for case in cases if isinstance(case, dict)]
    if manifest_ids != case_ids:
        errors.append("manifest case order must exactly match the split file")
    for duplicate in duplicates([case_id for case_id in manifest_ids if isinstance(case_id, str)]):
        errors.append(f"duplicate manifest case id: {duplicate}")

    admission_policy = manifest.get("admission_policy")
    if not isinstance(admission_policy, dict):
        admission_policy = {}
        errors.append("manifest.admission_policy must be an object")
    freeze = manifest.get("freeze")
    if not isinstance(freeze, dict):
        freeze = {}
        errors.append("manifest.freeze must be an object")

    if profile == "clean60":
        if admission_policy.get("model_result_used_for_admission") is not False:
            errors.append("clean60 admission_policy.model_result_used_for_admission must be false")
        if admission_policy.get("case_ids_opaque_in_prompt") is not True:
            errors.append("clean60 admission_policy.case_ids_opaque_in_prompt must be true")
        if freeze.get("frozen") is not True:
            errors.append("clean60 freeze.frozen must be true before benchmark runs")

    bucket_counts = {bucket: 0 for bucket in BUCKETS}
    source_counts = {category: 0 for category in SOURCE_CATEGORIES}
    prog_type_counts: dict[str, int] = {}
    helper_or_state_count = 0
    realish_count = 0
    hash_mismatches: list[str] = []
    per_case_reports: list[dict[str, Any]] = []

    for index, raw_case in enumerate(cases):
        if not isinstance(raw_case, dict):
            errors.append(f"manifest.cases[{index}] must be an object")
            continue
        case = {**defaults, **raw_case}
        case_id = case.get("case_id")
        if not isinstance(case_id, str):
            errors.append(f"manifest.cases[{index}].case_id must be a string")
            continue

        missing_fields = [
            field
            for field in [
                "bucket",
                "source_category",
                "prog_type",
                "origin",
                "review_status",
                "oracle_kind",
                "requires_helper_or_state",
                "uses_success_predicate",
            ]
            if field not in case
        ]
        if missing_fields:
            errors.append(f"{case_id}: manifest missing fields: {', '.join(missing_fields)}")

        bucket = case.get("bucket")
        source_category = case.get("source_category")
        prog_type = case.get("prog_type")
        oracle_kind = case.get("oracle_kind")
        if bucket not in BUCKETS:
            errors.append(f"{case_id}: invalid bucket {bucket!r}")
        else:
            bucket_counts[bucket] += 1
        if source_category not in SOURCE_CATEGORIES:
            errors.append(f"{case_id}: invalid source_category {source_category!r}")
        else:
            source_counts[source_category] += 1
            if source_category in {"real_project_seed", "minimized_upstream_style"}:
                realish_count += 1
        if prog_type not in PROG_TYPES:
            errors.append(f"{case_id}: invalid prog_type {prog_type!r}")
        else:
            prog_type_counts[prog_type] = prog_type_counts.get(prog_type, 0) + 1
        if not isinstance(oracle_kind, list) or not oracle_kind:
            errors.append(f"{case_id}: oracle_kind must be a non-empty list")
        elif any(kind not in ORACLE_KINDS for kind in oracle_kind):
            errors.append(f"{case_id}: invalid oracle_kind entry")
        for bool_field in ["requires_helper_or_state", "uses_success_predicate"]:
            if not require_bool(case.get(bool_field)):
                errors.append(f"{case_id}: {bool_field} must be boolean")
        if case.get("requires_helper_or_state") is True:
            helper_or_state_count += 1

        computed_hash = None
        if case_id in known_cases:
            computed_hash = case_digest(known_cases[case_id])
        recorded_hash = case.get("case_sha256")
        if profile == "clean60":
            if case.get("review_status") != "independent_reviewed":
                errors.append(f"{case_id}: clean60 review_status must be independent_reviewed")
            if source_category == "dev_calibration":
                errors.append(f"{case_id}: clean60 case cannot use dev_calibration source_category")
            if not isinstance(recorded_hash, str):
                errors.append(f"{case_id}: clean60 case_sha256 is required")
            elif computed_hash is not None and recorded_hash != computed_hash:
                errors.append(f"{case_id}: case_sha256 does not match current case files")
                hash_mismatches.append(case_id)
        elif recorded_hash is not None and computed_hash is not None and recorded_hash != computed_hash:
            warnings.append(f"{case_id}: case_sha256 does not match current case files")
            hash_mismatches.append(case_id)

        per_case_reports.append(
            {
                "case": case_id,
                "bucket": bucket,
                "source_category": source_category,
                "prog_type": prog_type,
                "computed_case_sha256": computed_hash,
                "recorded_case_sha256": recorded_hash,
            }
        )

    if profile == "clean60":
        for bucket, target in CLEAN60_BUCKET_TARGETS.items():
            if bucket_counts.get(bucket, 0) != target:
                errors.append(f"clean60 bucket {bucket} must have exactly {target} cases")
        if prog_type_counts.get("xdp", 0) > 25:
            errors.append("clean60 xdp prog_type count must be <= 25")
        if realish_count < 20:
            errors.append("clean60 must include at least 20 real_project_seed/minimized_upstream_style cases")
        if helper_or_state_count < 20:
            errors.append("clean60 must include at least 20 helper/state-obligation cases")

    return (
        {
            "enabled": True,
            "path": str(manifest_path),
            "profile": profile,
            "case_count": len(cases),
            "bucket_counts": bucket_counts,
            "source_counts": source_counts,
            "prog_type_counts": prog_type_counts,
            "helper_or_state_count": helper_or_state_count,
            "realish_count": realish_count,
            "hash_mismatches": hash_mismatches,
            "warnings": warnings,
            "reports": per_case_reports,
        },
        errors,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", type=Path, required=True, help="Split file containing case ids.")
    parser.add_argument("--expected-count", type=int, help="Required number of cases.")
    parser.add_argument("--manifest", type=Path, help="Machine-readable split manifest.")
    parser.add_argument(
        "--profile",
        choices=["dev", "clean60"],
        help="Manifest policy profile to enforce. Defaults to clean60 for clean60 split names, dev otherwise.",
    )
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
    profile_errors: list[str] = []
    split_implies_clean = "clean60" in args.split.stem
    if split_implies_clean:
        profile = "clean60"
        if args.profile == "dev":
            profile_errors.append("clean60 split cannot use --profile dev")
    else:
        profile = args.profile or "dev"

    known_cases = case_index(root)
    split_duplicates = duplicates(case_ids)
    missing_cases = sorted(set(case_ids) - set(known_cases))
    overlap: dict[str, dict[str, Any]] = {}
    disallow_overlap_paths = list(args.disallow_overlap)
    if profile == "clean60":
        dev40_split = root / "bpfix-test" / "splits" / "dev40.txt"
        explicit_paths = {path.resolve() for path in disallow_overlap_paths}
        if args.split.resolve() != dev40_split.resolve() and dev40_split.resolve() not in explicit_paths:
            disallow_overlap_paths.append(dev40_split)

    for other_split in disallow_overlap_paths:
        other_case_ids = run_suite.read_split_file(other_split)
        shared = sorted(set(case_ids) & set(other_case_ids))
        content_shared = overlapping_fingerprints(case_ids, other_case_ids, known_cases)
        overlap[str(other_split)] = {
            "case_ids": shared,
            "content": content_shared,
        }

    errors: list[str] = []
    errors.extend(profile_errors)
    if expected_count is not None and len(case_ids) != expected_count:
        errors.append(f"expected {expected_count} cases, found {len(case_ids)}")
    if split_duplicates:
        errors.append(f"duplicate case ids: {', '.join(split_duplicates)}")
    if missing_cases:
        errors.append(f"unknown case ids: {', '.join(missing_cases)}")
    for other_split, overlap_report in overlap.items():
        shared = overlap_report["case_ids"]
        if shared:
            errors.append(f"overlap with {other_split}: {', '.join(shared)}")
        for fingerprint_name, matches in overlap_report["content"].items():
            if matches:
                formatted = ", ".join(
                    f"{match['case']}~{match['overlaps_case']}" for match in matches
                )
                errors.append(f"{fingerprint_name} content overlap with {other_split}: {formatted}")

    manifest_summary: dict[str, Any] = {"enabled": False}
    if profile == "clean60" and args.manifest is None:
        errors.append("clean60 profile requires --manifest")
    if args.manifest is not None:
        manifest_summary, manifest_errors = audit_manifest(
            manifest=read_manifest(args.manifest),
            manifest_path=args.manifest,
            case_ids=case_ids,
            known_cases=known_cases,
            profile=profile,
        )
        errors.extend(manifest_errors)

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
        "profile": profile,
        "actual_count": len(case_ids),
        "duplicates": split_duplicates,
        "missing_cases": missing_cases,
        "overlap": overlap,
        "manifest": manifest_summary,
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
