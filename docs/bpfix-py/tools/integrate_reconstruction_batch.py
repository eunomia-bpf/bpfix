#!/usr/bin/env python3
"""Integrate a reviewed reconstruction batch into bpfix-bench metadata."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ARCHIVE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ARCHIVE_ROOT.parents[1]
if str(ARCHIVE_ROOT) not in sys.path:
    sys.path.insert(0, str(ARCHIVE_ROOT))

from tools.sync_external_raw_bench import dump_yaml, raw_bucket


NON_REPLAY_STATUSES = {
    "attempted_accepted",
    "attempted_failed",
    "attempted_unknown",
    "candidate_for_replay",
    "environment_required",
    "missing_source",
    "missing_verifier_log",
    "not_reconstructable_from_diff",
    "out_of_scope_non_verifier",
    "replay_reject_no_rejected_insn",
}
ALLOWED_STATUSES = {"replay_valid", *NON_REPLAY_STATUSES}


@dataclass(frozen=True)
class BatchRow:
    raw_id: str
    outcome: str
    classification: str
    reason: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="docs/tmp/reconstruction-batch-XX.md")
    parser.add_argument("--bench-root", type=Path, default=PROJECT_ROOT / "bpfix-bench")
    parser.add_argument("--apply", action="store_true", help="write metadata updates")
    args = parser.parse_args(argv)

    bench_root = args.bench_root.resolve()
    rows = parse_batch_report(args.report)
    result = integrate_batch(bench_root, rows, apply=args.apply)
    print(dump_yaml(result), end="")
    return 0 if not result["errors"] else 1


def parse_batch_report(report_path: Path) -> list[BatchRow]:
    text = report_path.read_text(encoding="utf-8")
    rows: list[BatchRow] = []
    in_record_results = False

    for line in text.splitlines():
        if line.startswith("## "):
            in_record_results = line.strip() == "## Record Results"
            continue
        if not in_record_results or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        if cells[0].lower() == "raw_id" or set(cells[0]) <= {"-"}:
            continue
        raw_id = clean_cell(cells[0])
        classification = clean_cell(cells[2])
        if not raw_id or not classification:
            continue
        rows.append(
            BatchRow(
                raw_id=raw_id,
                outcome=clean_cell(cells[1]),
                classification=classification,
                reason=clean_cell(cells[3]),
            )
        )

    if not rows:
        raise SystemExit(f"no Record Results rows found in {report_path}")
    duplicate_ids = sorted({row.raw_id for row in rows if sum(r.raw_id == row.raw_id for r in rows) > 1})
    if duplicate_ids:
        raise SystemExit(f"duplicate raw IDs in {report_path}: {', '.join(duplicate_ids)}")
    return rows


def integrate_batch(bench_root: Path, rows: list[BatchRow], apply: bool) -> dict[str, Any]:
    manifest_path = bench_root / "manifest.yaml"
    index_path = bench_root / "raw" / "index.yaml"
    manifest = load_yaml(manifest_path)
    index = load_yaml(index_path)
    manifest_cases = manifest.setdefault("cases", [])
    manifest_by_id = {
        entry.get("case_id"): entry
        for entry in manifest_cases
        if isinstance(entry, dict) and isinstance(entry.get("case_id"), str)
    }
    index_by_id = {
        entry.get("raw_id"): entry
        for entry in index.get("entries") or []
        if isinstance(entry, dict) and isinstance(entry.get("raw_id"), str)
    }

    summary: dict[str, Any] = {
        "apply": apply,
        "rows": len(rows),
        "admitted": [],
        "updated_raw": [],
        "missing_raw": [],
        "skipped_index": [],
        "errors": [],
    }

    raw_updates: dict[Path, dict[str, Any]] = {}
    for row in rows:
        if row.classification not in ALLOWED_STATUSES:
            summary["errors"].append(f"{row.raw_id}: unsupported classification {row.classification!r}")
            continue
        raw_path = raw_record_path(bench_root, index_by_id, row.raw_id)
        case_path = bench_root / "cases" / row.raw_id

        if row.classification == "replay_valid":
            case_yaml_path = case_path / "case.yaml"
            if not case_yaml_path.exists():
                summary["errors"].append(f"{row.raw_id}: replay_valid but missing {case_yaml_path}")
                continue
            case_data = load_yaml(case_yaml_path)
            manifest_entry = manifest_entry_from_case(row.raw_id, case_data)
            if row.raw_id in manifest_by_id:
                manifest_by_id[row.raw_id].update(manifest_entry)
            else:
                manifest_cases.append(manifest_entry)
                manifest_by_id[row.raw_id] = manifest_entry
            summary["admitted"].append(row.raw_id)

        if raw_path and raw_path.exists():
            raw = load_yaml(raw_path)
            update_reproduction(raw, row)
            raw_updates[raw_path] = raw
            summary["updated_raw"].append(str(raw_path.relative_to(PROJECT_ROOT)))
        else:
            summary["missing_raw"].append(row.raw_id)

        entry = index_by_id.get(row.raw_id)
        if entry:
            entry["reproduction_status"] = row.classification
            if row.classification == "replay_valid":
                entry["case_path"] = f"cases/{row.raw_id}"
                entry["artifact_path"] = f"cases/{row.raw_id}"
            else:
                entry["case_path"] = None
                entry["artifact_path"] = None
        else:
            summary["skipped_index"].append(row.raw_id)

    rebuild_index_counts(index)

    if apply and not summary["errors"]:
        manifest_path.write_text(dump_yaml(manifest), encoding="utf-8")
        for raw_path, raw in sorted(raw_updates.items()):
            raw_path.write_text(dump_yaml(raw), encoding="utf-8")
        index_path.write_text(dump_yaml(index), encoding="utf-8")

    return summary


def manifest_entry_from_case(case_id: str, case_data: dict[str, Any]) -> dict[str, Any]:
    source = mapping(case_data.get("source"))
    capture = mapping(case_data.get("capture"))
    reporting = mapping(case_data.get("reporting"))
    return {
        "case_id": case_id,
        "path": f"cases/{case_id}",
        "source_kind": source.get("kind"),
        "family_id": reporting.get("family_id") or case_id,
        "representative": reporting.get("representative", True),
        "capture_id": capture.get("capture_id"),
    }


def update_reproduction(raw: dict[str, Any], row: BatchRow) -> None:
    reproduction = raw.setdefault("reproduction", {})
    reproduction["status"] = row.classification
    if row.classification == "replay_valid":
        reproduction["case_id"] = row.raw_id
        reproduction["case_path"] = f"cases/{row.raw_id}"
        reproduction["artifact_path"] = f"cases/{row.raw_id}"
        reproduction["reason"] = "admitted_to_bpfix_bench_cases"
    else:
        reproduction["case_id"] = None
        reproduction["case_path"] = None
        reproduction["artifact_path"] = None
        reproduction["reason"] = row.reason or row.classification


def raw_record_path(bench_root: Path, index_by_id: dict[str, dict[str, Any]], raw_id: str) -> Path | None:
    entry = index_by_id.get(raw_id)
    if entry and isinstance(entry.get("path"), str):
        return bench_root / entry["path"]
    bucket = "so" if raw_id.startswith("stackoverflow-") else "gh"
    candidate = bench_root / "raw" / bucket / f"{raw_id}.yaml"
    return candidate if candidate.exists() else None


def rebuild_index_counts(index: dict[str, Any]) -> None:
    counts: dict[str, dict[str, int]] = {}
    for entry in index.get("entries") or []:
        source_kind = entry.get("source_kind")
        status = entry.get("reproduction_status")
        if not source_kind or not status:
            continue
        bucket = raw_bucket(str(source_kind))
        for key in (bucket, "all"):
            counts.setdefault(key, {})
            counts[key]["total"] = counts[key].get("total", 0) + 1
            counts[key][status] = counts[key].get(status, 0) + 1
    index["counts"] = counts


def clean_cell(value: str) -> str:
    value = re.sub(r"<br\\s*/?>", " ", value)
    value = value.replace("`", "")
    value = re.sub(r"\\s+", " ", value)
    return value.strip()


def mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    return data if isinstance(data, dict) else {}


if __name__ == "__main__":
    raise SystemExit(main())
