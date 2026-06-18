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
ORACLE_KINDS = {
    "compile",
    "verifier_load",
    "bpftool_prog_run",
    "attach_or_runtime",
    "environment_config",
    "custom_oracle",
    "helper_state",
    "proof_predicate",
}
BASE_CLEAN_ORACLE_KINDS = {"compile", "verifier_load"}
CLEAN_SEMANTIC_ORACLE_KINDS = {
    "bpftool_prog_run",
    "attach_or_runtime",
    "environment_config",
    "custom_oracle",
}
ALLOWED_EXCLUSION_REASONS = {
    "verifier_accepts",
    "unstable",
    "not_reproducible",
    "oracle_insufficient",
    "bpfix_unsupported",
    "duplicate_or_near_duplicate",
    "out_of_scope",
    "license_unclear",
}
REQUIRED_CLEAN_ADMISSION_FLAGS = {
    "model_result_used_for_admission": False,
    "case_ids_opaque_in_prompt": True,
    "result_blind_case_selection": True,
    "admitted_before_first_clean_run": True,
    "prompt_manifest_required": True,
}
CANDIDATE_ADMISSION_FLAGS = {
    "model_result_used_for_admission": False,
    "case_ids_opaque_in_prompt": True,
    "result_blind_case_selection": True,
}
CLEAN60_BUCKET_TARGETS = {
    "proof_lifecycle": 18,
    "source_object_correlation": 12,
    "modern_bpf_protocol": 15,
    "helper_memory_contract": 8,
    "environment_config_boundary": 7,
}
MANIFEST_PROFILES = {
    "dev": "dev_calibration",
    "candidate": "candidate_staging",
    "clean60": "clean_heldout",
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


def bpfix_bench_source_fingerprints(root: Path) -> dict[str, list[str]]:
    cases_root = root / "bpfix-bench" / "cases"
    fingerprints: dict[str, list[str]] = {}
    if not cases_root.exists():
        return fingerprints
    for source in sorted(cases_root.rglob("*.c")):
        digest = file_digest(source)
        fingerprints.setdefault(digest, []).append(str(source.relative_to(root)))
    return fingerprints


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


def manifest_case_fingerprints(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    manifest = read_manifest(path)
    defaults = manifest.get("case_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        return {}
    fingerprints: dict[str, dict[str, str]] = {}
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            continue
        case = {**defaults, **raw_case}
        case_id = case.get("case_id")
        if not isinstance(case_id, str):
            continue
        values: dict[str, str] = {}
        for key in ["case_sha256", "buggy_source_sha256"]:
            if isinstance(case.get(key), str):
                values[key] = case[key]
        if values:
            fingerprints[case_id] = values
    return fingerprints


def manifest_case_oracle_kinds(manifest: dict[str, Any]) -> dict[str, list[str]]:
    defaults = manifest.get("case_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        return {}
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


def manifest_cases_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    defaults = manifest.get("case_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        return {}
    values: dict[str, dict[str, Any]] = {}
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            continue
        case = {**defaults, **raw_case}
        case_id = case.get("case_id")
        if isinstance(case_id, str):
            values[case_id] = case
    return values


def missing_manifest_fingerprints(path: Path, case_ids: list[str]) -> list[str]:
    if not path.exists():
        return []
    fingerprints = manifest_case_fingerprints(path)
    missing: list[str] = []
    for case_id in case_ids:
        values = fingerprints.get(case_id, {})
        if "case_sha256" not in values or "buggy_source_sha256" not in values:
            missing.append(case_id)
    return missing


def split_manifest_path(split: Path, root: Path) -> Path:
    splits_dir = root / "bpfix-test" / "splits"
    known = {
        (splits_dir / "dev40.txt").resolve(): splits_dir / "dev40.manifest.json",
        (splits_dir / "real-seed-candidates.txt").resolve(): splits_dir / "real-seed-candidates.manifest.json",
        (splits_dir / "clean60.txt").resolve(): splits_dir / "clean60.manifest.json",
    }
    return known.get(split.resolve(), split.with_suffix(".manifest.json"))


def overlapping_fingerprints(
    current_ids: list[str],
    other_ids: list[str],
    known_cases: dict[str, Path],
    *,
    other_manifest: Path | None = None,
) -> dict[str, list[dict[str, str]]]:
    current = case_fingerprints(current_ids, known_cases)
    other = case_fingerprints(other_ids, known_cases)
    if other_manifest is not None:
        for case_id, values in manifest_case_fingerprints(other_manifest).items():
            other.setdefault(case_id, {}).update(values)
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


def require_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def audit_selection_protocol(
    *,
    manifest: dict[str, Any],
    errors: list[str],
    label: str,
) -> dict[str, Any]:
    protocol = manifest.get("selection_protocol")
    if not isinstance(protocol, dict):
        errors.append(f"{label} selection_protocol must be an object")
        protocol = {}
    required_strings = [
        "case_source_policy",
        "admission_order_policy",
        "review_policy",
        "model_result_blinding_policy",
        "near_duplicate_policy",
    ]
    for field in required_strings:
        if not require_nonempty_string(protocol.get(field)):
            errors.append(f"{label} selection_protocol.{field} must be a non-empty string")
    return protocol


def audit_exclusion_ledger(
    *,
    manifest: dict[str, Any],
    errors: list[str],
    label: str,
) -> dict[str, Any]:
    ledger = manifest.get("seed_exclusion_ledger")
    if not isinstance(ledger, list):
        errors.append(f"{label} seed_exclusion_ledger must be a list")
        ledger = []
    reason_counts = {reason: 0 for reason in ALLOWED_EXCLUSION_REASONS}
    for index, row in enumerate(ledger):
        if not isinstance(row, dict):
            errors.append(f"seed_exclusion_ledger[{index}] must be an object")
            continue
        seed = row.get("seed")
        reason = row.get("reason")
        notes = row.get("notes")
        if not require_nonempty_string(seed):
            errors.append(f"seed_exclusion_ledger[{index}].seed must be a non-empty string")
        if reason not in ALLOWED_EXCLUSION_REASONS:
            errors.append(f"seed_exclusion_ledger[{index}].reason has invalid value {reason!r}")
        else:
            reason_counts[reason] += 1
        if not require_nonempty_string(notes):
            errors.append(f"seed_exclusion_ledger[{index}].notes must be a non-empty string")
        if row.get("model_result_used") is not False:
            errors.append(f"seed_exclusion_ledger[{index}].model_result_used must be false")
    return {
        "entries": len(ledger),
        "reason_counts": reason_counts,
    }


def audit_candidate_seed_ledger(
    *,
    manifest: dict[str, Any],
    case_ids: list[str],
    errors: list[str],
    label: str,
) -> dict[str, Any]:
    ledger = manifest.get("candidate_seed_ledger")
    if not isinstance(ledger, list):
        errors.append(f"{label} candidate_seed_ledger must be a list")
        ledger = []

    admitted_by_case: dict[str, int] = {}
    excluded_count = 0
    for index, row in enumerate(ledger):
        if not isinstance(row, dict):
            errors.append(f"candidate_seed_ledger[{index}] must be an object")
            continue
        decision = row.get("decision")
        seed = row.get("seed")
        notes = row.get("notes")
        if not require_nonempty_string(seed):
            errors.append(f"candidate_seed_ledger[{index}].seed must be a non-empty string")
        if decision not in {"admitted", "excluded"}:
            errors.append(f"candidate_seed_ledger[{index}].decision must be 'admitted' or 'excluded'")
        if row.get("decision_made_before_model_eval") is not True:
            errors.append(f"candidate_seed_ledger[{index}].decision_made_before_model_eval must be true")
        if row.get("model_result_used") is not False:
            errors.append(f"candidate_seed_ledger[{index}].model_result_used must be false")
        if not require_nonempty_string(notes):
            errors.append(f"candidate_seed_ledger[{index}].notes must be a non-empty string")

        if decision == "admitted":
            case_id = row.get("case_id")
            if not isinstance(case_id, str):
                errors.append(f"candidate_seed_ledger[{index}].case_id must be a string for admitted seeds")
            elif case_id not in case_ids:
                errors.append(f"candidate_seed_ledger[{index}].case_id {case_id!r} is not in split")
            else:
                admitted_by_case[case_id] = admitted_by_case.get(case_id, 0) + 1
        elif decision == "excluded":
            excluded_count += 1
            reason = row.get("reason")
            if reason not in ALLOWED_EXCLUSION_REASONS:
                errors.append(f"candidate_seed_ledger[{index}].reason has invalid value {reason!r}")

    for case_id in case_ids:
        count = admitted_by_case.get(case_id, 0)
        if count == 0:
            errors.append(f"{case_id}: {label} candidate_seed_ledger missing admitted row")
        elif count > 1:
            errors.append(f"{case_id}: {label} candidate_seed_ledger has duplicate admitted rows")

    return {
        "entries": len(ledger),
        "admitted": sum(1 for row in ledger if isinstance(row, dict) and row.get("decision") == "admitted"),
        "excluded": excluded_count,
    }


def audit_case_review_contract(
    case_id: str,
    case: dict[str, Any],
    errors: list[str],
    *,
    label: str,
) -> dict[str, Any]:
    source_category = case.get("source_category")
    review = case.get("review")
    if not isinstance(review, dict):
        errors.append(f"{case_id}: {label} review must be an object")
        review = {}
    for field in ["reviewer", "reviewed_at", "bug_summary", "oracle_rationale", "provenance_rationale"]:
        if not require_nonempty_string(review.get(field)):
            errors.append(f"{case_id}: {label} review.{field} must be a non-empty string")
    if review.get("bug_confirmed") is not True:
        errors.append(f"{case_id}: {label} review.bug_confirmed must be true")
    if review.get("oracle_adequate") is not True:
        errors.append(f"{case_id}: {label} review.oracle_adequate must be true")
    if review.get("not_seen_in_prior_eval") is not True:
        errors.append(f"{case_id}: {label} review.not_seen_in_prior_eval must be true")

    provenance = case.get("provenance")
    if not isinstance(provenance, dict):
        errors.append(f"{case_id}: {label} provenance must be an object")
        provenance = {}
    for field in ["seed_type", "source", "license", "minimization"]:
        if not require_nonempty_string(provenance.get(field)):
            errors.append(f"{case_id}: {label} provenance.{field} must be a non-empty string")
    if source_category == "real_project_seed":
        for field in ["upstream_project", "upstream_ref", "upstream_path", "upstream_license"]:
            if not require_nonempty_string(provenance.get(field)):
                errors.append(f"{case_id}: {label} real_project_seed provenance.{field} must be a non-empty string")
    if provenance.get("derived_from_dev40") is not False:
        errors.append(f"{case_id}: {label} provenance.derived_from_dev40 must be false")
    if provenance.get("model_result_used") is not False:
        errors.append(f"{case_id}: {label} provenance.model_result_used must be false")

    oracle_obligation = case.get("oracle_obligation")
    if not isinstance(oracle_obligation, dict):
        errors.append(f"{case_id}: {label} oracle_obligation must be an object")
        oracle_obligation = {}
    for field in ["functional_semantics", "verifier_reject_reason", "success_criteria"]:
        values = oracle_obligation.get(field)
        if not isinstance(values, list) or not values or any(not require_nonempty_string(value) for value in values):
            errors.append(f"{case_id}: {label} oracle_obligation.{field} must be a non-empty string list")

    return {
        "reviewer": review.get("reviewer"),
        "reviewed_at": review.get("reviewed_at"),
        "source": provenance.get("source"),
        "seed_type": provenance.get("seed_type"),
    }


def audit_manifest(
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    expected_split_id: str,
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
    expected_profile = MANIFEST_PROFILES[profile]
    if manifest.get("profile") != expected_profile:
        errors.append(f"manifest.profile must be {expected_profile!r}")
    if manifest.get("split_id") != expected_split_id:
        errors.append(f"manifest.split_id must be {expected_split_id!r}")

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

    selection_protocol: dict[str, Any] = {}
    exclusion_summary: dict[str, Any] = {"entries": 0, "reason_counts": {}}
    candidate_seed_summary: dict[str, Any] = {"entries": 0, "admitted": 0, "excluded": 0}
    if profile == "candidate":
        for key, expected in CANDIDATE_ADMISSION_FLAGS.items():
            if admission_policy.get(key) is not expected:
                errors.append(f"candidate admission_policy.{key} must be {str(expected).lower()}")
        if freeze.get("frozen") is not False:
            errors.append("candidate freeze.frozen must be false until promotion to clean60")
        selection_protocol = audit_selection_protocol(manifest=manifest, errors=errors, label="candidate")
        exclusion_summary = audit_exclusion_ledger(manifest=manifest, errors=errors, label="candidate")
        candidate_seed_summary = audit_candidate_seed_ledger(
            manifest=manifest,
            case_ids=case_ids,
            errors=errors,
            label="candidate",
        )
    elif profile == "clean60":
        for key, expected in REQUIRED_CLEAN_ADMISSION_FLAGS.items():
            if admission_policy.get(key) is not expected:
                errors.append(f"clean60 admission_policy.{key} must be {str(expected).lower()}")
        if freeze.get("frozen") is not True:
            errors.append("clean60 freeze.frozen must be true before benchmark runs")
        selection_protocol = audit_selection_protocol(manifest=manifest, errors=errors, label="clean60")
        exclusion_summary = audit_exclusion_ledger(manifest=manifest, errors=errors, label="clean60")
        candidate_seed_summary = audit_candidate_seed_ledger(
            manifest=manifest,
            case_ids=case_ids,
            errors=errors,
            label="clean60",
        )

    bucket_counts = {bucket: 0 for bucket in BUCKETS}
    source_counts = {category: 0 for category in SOURCE_CATEGORIES}
    prog_type_counts: dict[str, int] = {}
    helper_or_state_count = 0
    realish_count = 0
    hash_mismatches: list[str] = []
    per_case_reports: list[dict[str, Any]] = []
    clean_buggy_source_hashes: dict[str, str] = {}

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
            if source_category == "real_project_seed":
                realish_count += 1
            if (
                profile == "candidate"
                and expected_split_id == "real-seed-candidates"
                and source_category != "real_project_seed"
            ):
                errors.append(f"{case_id}: real-seed-candidates requires source_category real_project_seed")
        if prog_type not in PROG_TYPES:
            errors.append(f"{case_id}: invalid prog_type {prog_type!r}")
        else:
            prog_type_counts[prog_type] = prog_type_counts.get(prog_type, 0) + 1
        if not isinstance(oracle_kind, list) or not oracle_kind:
            errors.append(f"{case_id}: oracle_kind must be a non-empty list")
        elif any(kind not in ORACLE_KINDS for kind in oracle_kind):
            errors.append(f"{case_id}: invalid oracle_kind entry")
        elif profile in {"candidate", "clean60"}:
            label = "candidate" if profile == "candidate" else "clean60"
            oracle_kind_set = set(oracle_kind)
            missing_oracles = sorted(BASE_CLEAN_ORACLE_KINDS - oracle_kind_set)
            if missing_oracles:
                errors.append(f"{case_id}: {label} oracle_kind missing: {', '.join(missing_oracles)}")
            if not CLEAN_SEMANTIC_ORACLE_KINDS & oracle_kind_set:
                errors.append(
                    f"{case_id}: {label} oracle_kind requires one semantic oracle: "
                    + ", ".join(sorted(CLEAN_SEMANTIC_ORACLE_KINDS))
                )
            if case.get("uses_success_predicate") is True and "proof_predicate" not in oracle_kind_set:
                errors.append(f"{case_id}: {label} uses_success_predicate requires oracle_kind proof_predicate")
            if (
                case.get("requires_helper_or_state") is True
                and not {"helper_state", "proof_predicate"} & oracle_kind_set
            ):
                errors.append(
                    f"{case_id}: {label} requires_helper_or_state requires oracle_kind helper_state or proof_predicate"
                )
        for bool_field in ["requires_helper_or_state", "uses_success_predicate"]:
            if not require_bool(case.get(bool_field)):
                errors.append(f"{case_id}: {bool_field} must be boolean")
        if case.get("requires_helper_or_state") is True:
            helper_or_state_count += 1

        computed_hash = None
        computed_buggy_source_hash = None
        if case_id in known_cases:
            case_dir = known_cases[case_id]
            computed_hash = case_digest(case_dir)
            computed_buggy_source_hash = file_digest(case_dir / "buggy.bpf.c")
        recorded_hash = case.get("case_sha256")
        recorded_buggy_source_hash = case.get("buggy_source_sha256")
        if profile in {"candidate", "clean60"}:
            label = "candidate" if profile == "candidate" else "clean60"
            review_report = audit_case_review_contract(case_id, case, errors, label=label)
            if not require_nonempty_string(case.get("origin")):
                errors.append(f"{case_id}: {label} origin must be a non-empty string")
            allowed_review_statuses = (
                {"candidate_reviewed", "independent_reviewed"}
                if profile == "candidate"
                else {"independent_reviewed"}
            )
            if case.get("review_status") not in allowed_review_statuses:
                expected_status = "candidate_reviewed or independent_reviewed" if profile == "candidate" else "independent_reviewed"
                errors.append(f"{case_id}: {label} review_status must be {expected_status}")
            reviewer = review_report.get("reviewer")
            if profile == "clean60" and isinstance(reviewer, str) and "required before paper use" in reviewer.lower():
                errors.append(f"{case_id}: clean60 review_status contradicts review.reviewer")
            if source_category == "dev_calibration":
                errors.append(f"{case_id}: {label} case cannot use dev_calibration source_category")
            if not isinstance(recorded_hash, str):
                errors.append(f"{case_id}: {label} case_sha256 is required")
            elif computed_hash is not None and recorded_hash != computed_hash:
                errors.append(f"{case_id}: case_sha256 does not match current case files")
                hash_mismatches.append(case_id)
            if not isinstance(recorded_buggy_source_hash, str):
                errors.append(f"{case_id}: {label} buggy_source_sha256 is required")
            elif (
                computed_buggy_source_hash is not None
                and recorded_buggy_source_hash != computed_buggy_source_hash
            ):
                errors.append(f"{case_id}: buggy_source_sha256 does not match current buggy.bpf.c")
                hash_mismatches.append(case_id)
            if isinstance(recorded_buggy_source_hash, str):
                previous = clean_buggy_source_hashes.get(recorded_buggy_source_hash)
                if previous is not None:
                    errors.append(
                        f"{case_id}: {label} buggy_source_sha256 duplicates {previous}"
                    )
                else:
                    clean_buggy_source_hashes[recorded_buggy_source_hash] = case_id
        elif recorded_hash is not None and computed_hash is not None and recorded_hash != computed_hash:
            if freeze.get("fingerprints_frozen") is True:
                errors.append(f"{case_id}: case_sha256 does not match frozen manifest fingerprint")
            else:
                warnings.append(f"{case_id}: case_sha256 does not match current case files")
            hash_mismatches.append(case_id)
        if profile != "clean60" and freeze.get("fingerprints_frozen") is True:
            if not isinstance(recorded_hash, str):
                errors.append(f"{case_id}: frozen manifest requires case_sha256")
            if not isinstance(recorded_buggy_source_hash, str):
                errors.append(f"{case_id}: frozen manifest requires buggy_source_sha256")
            elif (
                computed_buggy_source_hash is not None
                and recorded_buggy_source_hash != computed_buggy_source_hash
            ):
                errors.append(f"{case_id}: buggy_source_sha256 does not match frozen manifest fingerprint")
                hash_mismatches.append(case_id)

        per_case_reports.append(
            {
                "case": case_id,
                "bucket": bucket,
                "source_category": source_category,
                "prog_type": prog_type,
                "computed_case_sha256": computed_hash,
                "recorded_case_sha256": recorded_hash,
                "computed_buggy_source_sha256": computed_buggy_source_hash,
                "recorded_buggy_source_sha256": recorded_buggy_source_hash,
                **({"review": review_report} if profile in {"candidate", "clean60"} else {}),
            }
        )

    if profile == "clean60":
        for bucket, target in CLEAN60_BUCKET_TARGETS.items():
            if bucket_counts.get(bucket, 0) != target:
                errors.append(f"clean60 bucket {bucket} must have exactly {target} cases")
        if prog_type_counts.get("xdp", 0) > 25:
            errors.append("clean60 xdp prog_type count must be <= 25")
        if realish_count < 20:
            errors.append("clean60 must include at least 20 real_project_seed cases")
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
            "selection_protocol": selection_protocol,
            "candidate_seed_ledger": candidate_seed_summary,
            "seed_exclusion_ledger": exclusion_summary,
            "warnings": warnings,
            "reports": per_case_reports,
        },
        errors,
    )


def positive_count(value: Any) -> bool:
    return isinstance(value, int) and value > 0


def audit_manifest_oracle_alignment(
    *,
    manifest: dict[str, Any],
    case_reports: list[dict[str, Any]],
    errors: list[str],
    label: str,
) -> None:
    manifest_cases = manifest_cases_by_id(manifest)
    reports_by_case = {
        report.get("case"): report
        for report in case_reports
        if isinstance(report.get("case"), str)
    }
    for case_id, case in manifest_cases.items():
        report = reports_by_case.get(case_id)
        if report is None:
            errors.append(f"{case_id}: {label} oracle alignment requires a case audit report")
            continue
        test = report.get("test")
        if not isinstance(test, dict):
            errors.append(f"{case_id}: {label} oracle alignment requires parseable test.py summary")
            continue

        oracle_kind = case.get("oracle_kind")
        oracle_kind_set = set(oracle_kind) if isinstance(oracle_kind, list) else set()
        uses_success_predicate = case.get("uses_success_predicate")
        requires_helper_or_state = case.get("requires_helper_or_state")
        success_predicates = test.get("required_success_predicates")
        success_substrings = test.get("required_success_substrings")
        functional_tests = test.get("functional_tests")
        has_success_predicate = positive_count(success_predicates)
        has_success_substring = positive_count(success_substrings)
        has_functional_tests = positive_count(functional_tests)
        has_custom_oracle = test.get("custom_oracle") is True

        if "bpftool_prog_run" in oracle_kind_set and not has_functional_tests:
            errors.append(f"{case_id}: {label} oracle_kind bpftool_prog_run requires functional_tests in test.py")
        if "proof_predicate" in oracle_kind_set and not has_success_predicate:
            errors.append(
                f"{case_id}: {label} oracle_kind proof_predicate requires required_success_predicates in test.py"
            )
        if uses_success_predicate is True and not has_success_predicate:
            errors.append(f"{case_id}: {label} uses_success_predicate requires required_success_predicates")
        if uses_success_predicate is False and has_success_predicate:
            errors.append(f"{case_id}: {label} test.py has success predicates but manifest uses_success_predicate is false")
        if has_success_predicate and "proof_predicate" not in oracle_kind_set:
            errors.append(f"{case_id}: {label} success predicates require oracle_kind proof_predicate")
        if requires_helper_or_state is True and not (has_success_predicate or has_success_substring):
            errors.append(
                f"{case_id}: {label} requires_helper_or_state needs required_success_substrings or predicates"
            )
        if "helper_state" in oracle_kind_set and not (has_success_predicate or has_success_substring):
            errors.append(f"{case_id}: {label} oracle_kind helper_state needs success substring or predicate checks")
        if "custom_oracle" in oracle_kind_set and not has_custom_oracle:
            errors.append(f"{case_id}: {label} oracle_kind custom_oracle requires custom_oracle test summary")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", type=Path, required=True, help="Split file containing case ids.")
    parser.add_argument("--expected-count", type=int, help="Required number of cases.")
    parser.add_argument("--manifest", type=Path, help="Machine-readable split manifest.")
    parser.add_argument(
        "--profile",
        choices=["dev", "candidate", "clean60"],
        help="Manifest policy profile to enforce. Defaults to clean60 for clean60 split names, candidate for real-seed-candidates, dev otherwise.",
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
    split_implies_candidate = args.split.stem == "real-seed-candidates"
    if split_implies_clean:
        profile = "clean60"
        if args.profile in {"dev", "candidate"}:
            profile_errors.append(f"clean60 split cannot use --profile {args.profile}")
    elif split_implies_candidate:
        profile = args.profile or "candidate"
        if args.profile in {"dev", "clean60"}:
            profile_errors.append(f"real-seed-candidates split cannot use --profile {args.profile}")
    else:
        profile = args.profile or "dev"
    split_implies_dev40 = args.split.resolve() == (root / "bpfix-test" / "splits" / "dev40.txt").resolve()

    known_cases = case_index(root)
    bpfix_bench_sources = bpfix_bench_source_fingerprints(root) if profile in {"candidate", "clean60"} else {}
    split_duplicates = duplicates(case_ids)
    missing_cases = sorted(set(case_ids) - set(known_cases))
    overlap: dict[str, dict[str, Any]] = {}
    disallow_overlap_paths = list(args.disallow_overlap)
    if profile in {"candidate", "clean60"}:
        dev40_split = root / "bpfix-test" / "splits" / "dev40.txt"
        explicit_paths = {path.resolve() for path in disallow_overlap_paths}
        if args.split.resolve() != dev40_split.resolve() and dev40_split.resolve() not in explicit_paths:
            disallow_overlap_paths.append(dev40_split)

    for other_split in disallow_overlap_paths:
        other_case_ids = run_suite.read_split_file(other_split)
        shared = sorted(set(case_ids) & set(other_case_ids))
        other_manifest = split_manifest_path(other_split, root)
        content_shared = overlapping_fingerprints(
            case_ids,
            other_case_ids,
            known_cases,
            other_manifest=other_manifest,
        )
        overlap[str(other_split)] = {
            "case_ids": shared,
            "manifest": str(other_manifest) if other_manifest.exists() else None,
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
    bpfix_bench_overlap: list[dict[str, Any]] = []
    if bpfix_bench_sources:
        for case_id in case_ids:
            case_dir = known_cases.get(case_id)
            if case_dir is None:
                continue
            digest = file_digest(case_dir / "buggy.bpf.c")
            matches = bpfix_bench_sources.get(digest)
            if matches:
                bpfix_bench_overlap.append(
                    {
                        "case": case_id,
                        "buggy_source_sha256": digest,
                        "bpfix_bench_sources": matches,
                    }
                )
        if bpfix_bench_overlap:
            formatted = ", ".join(
                f"{match['case']}~{match['bpfix_bench_sources'][0]}" for match in bpfix_bench_overlap
            )
            errors.append(f"buggy.bpf.c content overlap with bpfix-bench: {formatted}")
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
        manifest_path = overlap_report.get("manifest")
        if manifest_path:
            missing_fingerprints = missing_manifest_fingerprints(Path(manifest_path), run_suite.read_split_file(Path(other_split)))
            if missing_fingerprints:
                errors.append(
                    f"overlap manifest {manifest_path} missing frozen fingerprints for: "
                    + ", ".join(missing_fingerprints)
                )

    manifest_summary: dict[str, Any] = {"enabled": False}
    manifest_payload: dict[str, Any] | None = None
    manifest_oracle_kinds: dict[str, list[str]] = {}
    if split_implies_dev40 and args.manifest is None:
        errors.append("dev40 split requires --manifest")
    if profile in {"candidate", "clean60"} and args.manifest is None:
        errors.append(f"{profile} profile requires --manifest")
    if args.manifest is not None:
        manifest_payload = read_manifest(args.manifest)
        manifest_oracle_kinds = manifest_case_oracle_kinds(manifest_payload)
        manifest_summary, manifest_errors = audit_manifest(
            manifest=manifest_payload,
            manifest_path=args.manifest,
            expected_split_id=args.split.stem,
            case_ids=case_ids,
            known_cases=known_cases,
            profile=profile,
        )
        errors.extend(manifest_errors)

    case_reports: list[dict[str, Any]] = []
    if args.audit_cases and not missing_cases and not split_duplicates:
        for case_id in case_ids:
            report = audit_cases.audit_case(
                known_cases[case_id],
                smoke=args.smoke,
                root=root,
                oracle_kind=manifest_oracle_kinds.get(case_id),
            )
            case_reports.append(report)
        failed_cases = [report["case"] for report in case_reports if not report["passed"]]
        if failed_cases:
            errors.append(f"case audit failed: {', '.join(failed_cases)}")
        if manifest_payload is not None and profile in {"candidate", "clean60"}:
            audit_manifest_oracle_alignment(
                manifest=manifest_payload,
                case_reports=case_reports,
                errors=errors,
                label=profile,
            )

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
        "bpfix_bench_overlap": bpfix_bench_overlap,
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
