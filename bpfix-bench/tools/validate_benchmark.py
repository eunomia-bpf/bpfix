#!/usr/bin/env python3
"""Validate and replay a bpfix benchmark directory."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

if __package__:
    from .benchmark_metadata import with_case_defaults
    from .replay_case import parse_verifier_log, replay_case
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from benchmark_metadata import with_case_defaults
    from replay_case import parse_verifier_log, replay_case


VALID_RECONSTRUCTIONS = {"original", "minimized", "reconstructed"}
VALID_EXTERNAL_MATCH = {"exact", "partial", "semantic", "not_applicable"}
VALID_SOURCE_KINDS = {"kernel_selftest", "stackoverflow", "github_issue", "github_commit"}
VALID_CASE_DEFAULT_FIELDS = {
    "reproducer": {"source_file", "build_command", "object_path", "load_command"},
    "capture": {"verifier_log", "capture_metadata", "log_quality"},
}
VALID_TAXONOMY_CLASSES = {
    "source_bug",
    "lowering_artifact",
    "environment_or_configuration",
    "verifier_limit",
    "verifier_false_positive",
}
REMOVED_CASE_FIELDS = {
    "capture": {
        "build_status": "success is validated by replay",
        "load_status": "verifier reject is validated by replay",
        "verifier_pass": "verifier reject is validated by replay",
        "captured_at": "capture timestamps belong in capture.yaml",
        "exit_code": "loader exit details belong in capture.yaml",
    },
    "reproducer": {
        "status": "manifest membership and replay validation define active cases",
        "language": "all current reproducers are BPF C; add language only when it varies",
    },
    "reporting": {
        "intentional_negative_test": "derived from source.kind for the current corpus",
    },
}
VERIFIER_PC_RE = re.compile(r"^\s*(\d+):")
SOURCE_COMMENT_RE = re.compile(r"^\s*;\s*(?P<source>.*?)(?:\s+@\s+[^@]+:\d+)?\s*$")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", type=Path, required=True, help="Benchmark root, e.g. bpfix-bench")
    parser.add_argument("--timeout-sec", type=int, default=60, help="Per-command timeout in seconds")
    args = parser.parse_args(argv)

    report = validate_benchmark(args.replay.resolve(), args.timeout_sec)
    report_path = args.replay / "replay-report.json"
    if args.replay.exists():
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


def validate_benchmark(benchmark_root: Path, timeout_sec: int) -> dict[str, Any]:
    report: dict[str, Any] = {
        "valid": False,
        "benchmark_root": str(benchmark_root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"total_cases": 0, "passed": 0, "failed": 0},
        "errors": [],
        "cases": [],
    }

    manifest_path = benchmark_root / "manifest.yaml"
    if not benchmark_root.exists():
        report["errors"].append(f"benchmark root does not exist: {benchmark_root}")
        return report
    if not manifest_path.exists():
        report["errors"].append(f"missing manifest: {manifest_path}")
        return report

    try:
        manifest = load_yaml_mapping(manifest_path)
    except Exception as exc:  # noqa: BLE001
        report["errors"].append(f"failed to read manifest.yaml: {exc}")
        return report

    report["errors"].extend(validate_manifest_metadata(manifest))
    if report["errors"]:
        return report

    entries = manifest.get("cases")
    if not isinstance(entries, list):
        report["errors"].append("manifest.cases must be a list")
        return report

    duplicate_errors = _duplicate_case_errors(entries)
    report["errors"].extend(duplicate_errors)

    try:
        legacy_rejected_indices = load_legacy_rejected_indices(benchmark_root)
    except Exception as exc:  # noqa: BLE001
        report["errors"].append(f"failed to read raw legacy instruction numbering: {exc}")
        return report

    case_entries = [entry for entry in entries if isinstance(entry, dict)]
    report["summary"]["total_cases"] = len(case_entries)

    for entry in case_entries:
        case_report = validate_case(benchmark_root, manifest, entry, timeout_sec, legacy_rejected_indices)
        report["cases"].append(case_report)
        if case_report["valid"]:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

    report["valid"] = not report["errors"] and report["summary"]["failed"] == 0
    return report


def validate_manifest_metadata(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(manifest.get("environment_id"), str) or not manifest.get("environment_id"):
        errors.append("manifest.environment_id must be a non-empty string")

    defaults_value = manifest.get("case_defaults")
    if defaults_value is None:
        return errors
    if not isinstance(defaults_value, dict):
        errors.append("manifest.case_defaults must be a mapping")
        return errors

    for section_name, section_defaults in defaults_value.items():
        if section_name not in VALID_CASE_DEFAULT_FIELDS:
            errors.append(f"invalid manifest.case_defaults section: {section_name!r}")
            continue
        if not isinstance(section_defaults, dict):
            errors.append(f"manifest.case_defaults.{section_name} must be a mapping")
            continue
        valid_fields = VALID_CASE_DEFAULT_FIELDS[section_name]
        for field, value in section_defaults.items():
            if field not in valid_fields:
                errors.append(f"invalid manifest.case_defaults.{section_name}.{field}")
                continue
            if not isinstance(value, str) or not value:
                errors.append(f"manifest.case_defaults.{section_name}.{field} must be a non-empty string")
    return errors


def validate_case(
    benchmark_root: Path,
    manifest: dict[str, Any],
    entry: dict[str, Any],
    timeout_sec: int,
    legacy_rejected_indices: dict[str, int] | None = None,
) -> dict[str, Any]:
    case_id = str(entry.get("case_id") or "<missing>")
    case_report: dict[str, Any] = {
        "case_id": case_id,
        "valid": False,
        "errors": [],
        "warnings": [],
        "manifest": _public_manifest_fields(entry),
        "replay": None,
        "fresh": None,
        "stored": None,
    }

    required_manifest = ["case_id", "path", "source_kind", "family_id", "representative", "capture_id"]
    require_fields(entry, required_manifest, "manifest case", case_report["errors"])

    path_value = entry.get("path")
    case_dir = benchmark_root / path_value if isinstance(path_value, str) else benchmark_root / "cases" / case_id
    case_yaml_path = case_dir / "case.yaml"
    if not case_dir.is_dir():
        case_report["errors"].append(f"missing case directory: {case_dir}")
        return case_report
    if not case_yaml_path.exists():
        case_report["errors"].append(f"missing case.yaml: {case_yaml_path}")
        return case_report

    try:
        case_data = load_yaml_mapping(case_yaml_path)
    except Exception as exc:  # noqa: BLE001
        case_report["errors"].append(f"failed to read case.yaml: {exc}")
        return case_report
    case_data = with_case_defaults(case_data, manifest)

    validate_case_metadata(case_dir, manifest, entry, case_data, case_report)
    legacy_rejected_idx = (legacy_rejected_indices or {}).get(case_id)
    validate_stored_artifacts(case_dir, case_data, case_report, legacy_rejected_idx)

    try:
        replay = replay_case(case_dir, case_data, timeout_sec=timeout_sec)
    except Exception as exc:  # noqa: BLE001
        case_report["errors"].append(f"replay failed before load comparison: {exc}")
        return case_report

    case_report["replay"] = {
        "build": command_summary(replay.build),
        "load": command_summary(replay.load),
        "log_source": replay.parsed_log.source,
    }
    fresh = asdict(replay.parsed_log)
    case_report["fresh"] = fresh

    if replay.build.timed_out:
        case_report["errors"].append("build command timed out")
    elif replay.build.returncode != 0:
        case_report["errors"].append(f"build command failed with exit code {replay.build.returncode}")

    if replay.load.timed_out:
        case_report["errors"].append("load command timed out")
    elif replay.load.returncode == 0:
        case_report["errors"].append("load command succeeded; expected verifier reject")

    capture = case_data.get("capture") or {}
    expected_terminal = capture.get("terminal_error")
    expected_idx = capture.get("rejected_insn_idx")
    expected_quality = capture.get("log_quality")

    if not fresh.get("terminal_error"):
        case_report["errors"].append("fresh replay did not produce a parseable verifier terminal error")
    elif expected_terminal != fresh["terminal_error"]:
        case_report["errors"].append(
            f"terminal_error mismatch: expected {expected_terminal!r}, got {fresh['terminal_error']!r}"
        )

    if fresh.get("rejected_insn_idx") is None:
        case_report["errors"].append("fresh replay did not produce a rejected instruction index")
    elif expected_idx != fresh["rejected_insn_idx"]:
        case_report["errors"].append(
            f"rejected_insn_idx mismatch: expected {expected_idx!r}, got {fresh['rejected_insn_idx']!r}"
        )

    if expected_quality and expected_quality != fresh.get("log_quality"):
        case_report["errors"].append(
            f"log_quality mismatch: expected {expected_quality!r}, got {fresh.get('log_quality')!r}"
        )

    validate_post_build_artifacts(case_dir, case_data, case_report)
    case_report["valid"] = not case_report["errors"]
    return case_report


def validate_case_metadata(
    case_dir: Path,
    manifest: dict[str, Any],
    entry: dict[str, Any],
    case_data: dict[str, Any],
    case_report: dict[str, Any],
) -> None:
    errors = case_report["errors"]
    case_id = entry.get("case_id")
    capture = mapping(case_data.get("capture"))
    label = mapping(case_data.get("label"))
    reproducer = mapping(case_data.get("reproducer"))
    source = mapping(case_data.get("source"))
    reporting = mapping(case_data.get("reporting"))
    external_match = mapping(case_data.get("external_match"))

    require_fields(case_data, ["schema_version", "case_id", "source", "reproducer", "capture", "label", "reporting"], "case", errors)
    require_fields(reproducer, ["reconstruction", "build_command", "load_command", "source_file", "object_path"], "reproducer", errors)
    require_fields(
        capture,
        [
            "capture_id",
            "environment_id",
            "verifier_log",
            "capture_metadata",
            "log_quality",
            "terminal_error",
            "rejected_insn_idx",
        ],
        "capture",
        errors,
    )
    require_fields(label, ["capture_id", "taxonomy_class"], "label", errors)
    require_fields(reporting, ["family_id", "representative"], "reporting", errors)
    validate_label_metadata(label, errors)

    if "split" in entry:
        errors.append("manifest case must not define split; bpfix-bench has a single case set")
    if "split" in reporting:
        errors.append("case.reporting must not define split; bpfix-bench has a single case set")
    if "quarantine" in reporting:
        errors.append("case.reporting must not define quarantine; keep non-primary cases outside bpfix-bench")

    compare(case_data.get("case_id"), case_id, "case.case_id", errors)
    compare(source.get("kind"), entry.get("source_kind"), "source.kind/source_kind", errors)
    if source.get("kind") not in VALID_SOURCE_KINDS:
        errors.append(f"invalid source.kind: {source.get('kind')!r}")
    if entry.get("source_kind") not in VALID_SOURCE_KINDS:
        errors.append(f"invalid manifest.source_kind: {entry.get('source_kind')!r}")
    compare(capture.get("capture_id"), entry.get("capture_id"), "capture.capture_id/manifest.capture_id", errors)
    compare(label.get("capture_id"), capture.get("capture_id"), "label.capture_id/capture.capture_id", errors)
    if "rejected_insn_idx" in label:
        errors.append("label.rejected_insn_idx is redundant; use capture.rejected_insn_idx")
    if "legacy_rejected_insn_idx" in label:
        errors.append("label.legacy_rejected_insn_idx is legacy numbering metadata; do not store it in case.yaml")
    compare(reporting.get("family_id"), entry.get("family_id"), "reporting.family_id/manifest.family_id", errors)
    compare(reporting.get("representative"), entry.get("representative"), "reporting.representative/manifest.representative", errors)

    for section_name, fields in REMOVED_CASE_FIELDS.items():
        section = mapping(case_data.get(section_name))
        for field, reason in fields.items():
            if field in section:
                errors.append(f"{section_name}.{field} is redundant in case.yaml: {reason}")

    if reproducer.get("reconstruction") not in VALID_RECONSTRUCTIONS:
        errors.append(f"invalid reproducer.reconstruction: {reproducer.get('reconstruction')!r}")
    if not entry.get("family_id"):
        errors.append("manifest family_id is required")
    if "representative" not in entry:
        errors.append("manifest representative is required")

    if external_match:
        status = external_match.get("status")
        if status not in VALID_EXTERNAL_MATCH:
            errors.append(f"invalid external_match.status: {status!r}")
        if source.get("kind") == "kernel_selftest" and status != "not_applicable":
            errors.append("kernel_selftest cases must use external_match.status == 'not_applicable'")
        if source.get("kind") in {"stackoverflow", "github_issue"} and status not in {"exact", "partial", "semantic"}:
            errors.append("Stack Overflow/GitHub cases must use exact, partial, or semantic external_match.status")
        if source.get("kind") == "github_commit" and status != "not_applicable":
            errors.append("commit-derived cases must use external_match.status == 'not_applicable'")

    if manifest.get("environment_id") and capture.get("environment_id"):
        compare(capture.get("environment_id"), manifest.get("environment_id"), "capture.environment_id/manifest.environment_id", errors)

    validate_capture_metadata(case_dir, case_data, manifest, case_report)


def validate_label_metadata(label: dict[str, Any], errors: list[str]) -> None:
    taxonomy_class = label.get("taxonomy_class")
    if taxonomy_class is None:
        return
    if not isinstance(taxonomy_class, str) or not taxonomy_class:
        errors.append("label.taxonomy_class must be a non-empty string")
    elif taxonomy_class not in VALID_TAXONOMY_CLASSES:
        errors.append(f"invalid label.taxonomy_class: {taxonomy_class!r}")

    for field in ("mechanism_tags", "obligation_ids", "evidence_tags"):
        value = label.get(field)
        if value is None:
            continue
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            errors.append(f"label.{field} must be a list of non-empty strings")


def validate_stored_artifacts(
    case_dir: Path,
    case_data: dict[str, Any],
    case_report: dict[str, Any],
    legacy_rejected_idx: int | None = None,
) -> None:
    errors = case_report["errors"]
    capture = mapping(case_data.get("capture"))
    source_kind = mapping(case_data.get("source")).get("kind")
    source_file = mapping(case_data.get("reproducer")).get("source_file")
    if isinstance(source_file, str):
        source_path = case_dir / source_file
        if not source_path.exists():
            errors.append(f"missing reproducer.source_file: {source_file}")

    verifier_log_value = capture.get("verifier_log")
    if not isinstance(verifier_log_value, str) or not verifier_log_value:
        return

    verifier_log_path = case_dir / verifier_log_value
    if not verifier_log_path.exists():
        errors.append(f"missing verifier log: {verifier_log_path}")
        return
    if verifier_log_path.stat().st_size == 0:
        errors.append(f"empty verifier log: {verifier_log_path}")
        return

    verifier_log = verifier_log_path.read_text(encoding="utf-8", errors="replace")
    parsed = parse_verifier_log(verifier_log, source=str(verifier_log_path.name))
    instruction_pcs = verifier_log_instruction_pcs(verifier_log)
    case_report["stored"] = {
        "verifier_log": verifier_log_value,
        "terminal_error": parsed.terminal_error,
        "rejected_insn_idx": parsed.rejected_insn_idx,
        "log_quality": parsed.log_quality,
        "instruction_pc_count": len(instruction_pcs),
    }

    if capture.get("terminal_error") and parsed.terminal_error != capture.get("terminal_error"):
        errors.append("capture.terminal_error does not match stored verifier.log")
    if parsed.rejected_insn_idx is None:
        errors.append("stored verifier.log has no parseable rejected instruction index")
    elif capture.get("rejected_insn_idx") != parsed.rejected_insn_idx:
        errors.append("capture.rejected_insn_idx does not match stored verifier.log")

    label = mapping(case_data.get("label"))
    root_pc = label.get("root_cause_insn_idx")
    if root_pc is not None:
        if not isinstance(root_pc, int):
            errors.append("label.root_cause_insn_idx must be an integer or null")
        elif root_pc not in instruction_pcs:
            max_pc = max(instruction_pcs) if instruction_pcs else None
            errors.append(
                "label.root_cause_insn_idx is outside the stored replay verifier-log "
                f"instruction numbering: root={root_pc!r}, max_pc={max_pc!r}"
            )
        else:
            validate_legacy_shadowed_root_line(
                verifier_log,
                capture,
                label,
                source_kind,
                root_pc,
                legacy_rejected_idx,
                errors,
            )

    for field in ("build_stdout", "build_stderr", "load_stdout", "load_stderr"):
        value = capture.get(field)
        if isinstance(value, str) and value and not (case_dir / value).exists():
            errors.append(f"missing capture artifact {field}: {value}")


def validate_post_build_artifacts(case_dir: Path, case_data: dict[str, Any], case_report: dict[str, Any]) -> None:
    reproducer = mapping(case_data.get("reproducer"))
    object_path_value = reproducer.get("object_path")
    if not isinstance(object_path_value, str) or not object_path_value:
        return
    object_path = case_dir / object_path_value
    if not object_path.exists():
        case_report["errors"].append(f"missing reproducer.object_path after build: {object_path_value}")


def validate_capture_metadata(
    case_dir: Path,
    case_data: dict[str, Any],
    manifest: dict[str, Any],
    case_report: dict[str, Any],
) -> None:
    capture = mapping(case_data.get("capture"))
    metadata_value = capture.get("capture_metadata")
    if not isinstance(metadata_value, str) or not metadata_value:
        case_report["errors"].append("capture.capture_metadata is required")
        return
    metadata_path = case_dir / metadata_value
    if not metadata_path.exists():
        case_report["errors"].append(f"missing capture metadata: {metadata_value}")
        return
    try:
        metadata = load_yaml_mapping(metadata_path)
    except Exception as exc:  # noqa: BLE001
        case_report["errors"].append(f"failed to read capture metadata {metadata_value}: {exc}")
        return

    reproducer = mapping(case_data.get("reproducer"))
    checks = [
        ("capture_id", capture.get("capture_id"), first_present(metadata, ["capture_id"], ["capture", "capture_id"])),
        ("environment_id", capture.get("environment_id") or manifest.get("environment_id"), first_present(metadata, ["environment_id"], ["capture", "environment_id"])),
        ("build_command", reproducer.get("build_command"), first_present(metadata, ["build_command"], ["reproducer", "build_command"], ["commands", "build"])),
        ("load_command", reproducer.get("load_command"), first_present(metadata, ["load_command"], ["reproducer", "load_command"], ["commands", "load"])),
    ]
    for name, expected, actual in checks:
        if actual is not None and expected is not None and actual != expected:
            case_report["errors"].append(f"capture metadata {name} mismatch: expected {expected!r}, got {actual!r}")

    source = mapping(case_data.get("source"))
    if source.get("kind") == "github_commit":
        source_artifact = mapping(metadata.get("source_artifact"))
        verifier_error_match = source_artifact.get("verifier_error_match")
        if verifier_error_match is not None and verifier_error_match != "not_applicable":
            case_report["errors"].append(
                "commit-derived capture metadata verifier_error_match must be 'not_applicable'"
            )


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise TypeError(f"{path} must contain a top-level mapping")
    return data


def mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def require_fields(mapping_value: dict[str, Any], fields: list[str], prefix: str, errors: list[str]) -> None:
    for field in fields:
        if field not in mapping_value or mapping_value.get(field) is None:
            errors.append(f"missing {prefix}.{field}")


def compare(left: Any, right: Any, label: str, errors: list[str]) -> None:
    if left != right:
        errors.append(f"{label} mismatch: {left!r} != {right!r}")


def first_present(mapping_value: dict[str, Any], *paths: list[str]) -> Any:
    for path in paths:
        value: Any = mapping_value
        for part in path:
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if value is not None:
            return value
    return None


def verifier_log_instruction_pcs(verifier_log: str) -> set[int]:
    pcs: set[int] = set()
    for line in verifier_log.splitlines():
        match = VERIFIER_PC_RE.match(line)
        if match:
            pcs.add(int(match.group(1)))
    return pcs


def verifier_log_source_comment_for_pc(verifier_log: str, pc: int) -> str | None:
    current_source: str | None = None
    result: str | None = None
    for line in verifier_log.splitlines():
        source_match = SOURCE_COMMENT_RE.match(line)
        if source_match:
            source = source_match.group("source").strip()
            if source:
                current_source = source
            continue
        pc_match = VERIFIER_PC_RE.match(line)
        if pc_match and int(pc_match.group(1)) == pc and current_source:
            # The live-register preamble can list the same PC without source
            # comments. Keep the last source-backed occurrence from the trace.
            result = current_source
    return result


def validate_legacy_shadowed_root_line(
    verifier_log: str,
    capture: dict[str, Any],
    label: dict[str, Any],
    source_kind: Any,
    root_pc: int,
    legacy_rejected_idx: int | None,
    errors: list[str],
) -> None:
    if source_kind not in {"stackoverflow", "github_issue", "github_commit"}:
        return

    replay_rejected_idx = capture.get("rejected_insn_idx")
    if legacy_rejected_idx is None or replay_rejected_idx == legacy_rejected_idx or root_pc != legacy_rejected_idx:
        return

    root_line = label.get("root_cause_line")
    if not isinstance(root_line, str) or not root_line:
        return

    replay_source = verifier_log_source_comment_for_pc(verifier_log, root_pc)
    if replay_source is None:
        return
    if normalize_source_line(replay_source) == normalize_source_line(root_line):
        return

    errors.append(
        "label.root_cause_insn_idx matches legacy rejected numbering while replay "
        "rejected_insn_idx changed, and the replay source line at that PC does not "
        "match label.root_cause_line: "
        f"root={root_pc!r}, legacy_rejected={legacy_rejected_idx!r}, "
        f"replay_rejected={replay_rejected_idx!r}, "
        f"replay_source={replay_source!r}, root_cause_line={root_line!r}"
    )


def normalize_source_line(line: str) -> str:
    return "".join(line.split())


def load_legacy_rejected_indices(benchmark_root: Path) -> dict[str, int]:
    path = benchmark_root / "raw" / "legacy-insn-numbering.yaml"
    if not path.exists():
        return {}

    raw = load_yaml_mapping(path)
    entries = raw.get("entries")
    if not isinstance(entries, list):
        raise ValueError("raw/legacy-insn-numbering.yaml entries must be a list")

    indices: dict[str, int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("raw/legacy-insn-numbering.yaml entries must be mappings")
        case_id = entry.get("case_id")
        legacy_idx = entry.get("legacy_rejected_insn_idx")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("legacy numbering entry case_id must be a non-empty string")
        if not isinstance(legacy_idx, int):
            raise ValueError(f"legacy numbering entry {case_id} has non-integer legacy_rejected_insn_idx")
        indices[case_id] = legacy_idx
    return indices


def command_summary(result: Any) -> dict[str, Any]:
    return {
        "command": result.command,
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "stdout_tail": tail(result.stdout),
        "stderr_tail": tail(result.stderr),
    }


def tail(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def _duplicate_case_errors(entries: list[Any]) -> list[str]:
    seen: set[str] = set()
    errors: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append("manifest.cases entries must be mappings")
            continue
        case_id = entry.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            errors.append("manifest case missing case_id")
            continue
        if case_id in seen:
            errors.append(f"duplicate manifest case_id: {case_id}")
        seen.add(case_id)
    return errors


def _public_manifest_fields(entry: dict[str, Any]) -> dict[str, Any]:
    fields = ("path", "source_kind", "family_id", "representative", "capture_id")
    return {field: entry.get(field) for field in fields}


if __name__ == "__main__":
    raise SystemExit(main())
