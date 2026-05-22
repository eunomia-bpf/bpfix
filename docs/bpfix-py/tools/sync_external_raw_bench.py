#!/usr/bin/env python3
"""Sync external SO/GH raw records into bpfix-bench/raw.

Raw records are intentionally broader than replayable benchmark cases:
every collected Stack Overflow question, GitHub issue, or GitHub commit-derived
candidate can live here even if it has not yet been reconstructed or replayed.
Only locally replayable verifier rejects should be admitted to bpfix-bench/cases.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml

ARCHIVE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ARCHIVE_ROOT.parents[1]
if str(ARCHIVE_ROOT) not in sys.path:
    sys.path.insert(0, str(ARCHIVE_ROOT))

from tools.replay_case import parse_verifier_log

DEFAULT_BENCH_ROOT = PROJECT_ROOT / "bpfix-bench"
DEFAULT_SO_ROOTS: list[Path] = []
DEFAULT_GH_ROOTS: list[Path] = []
VERIFIED_ROOTS: list[Path] = []


class RawDumper(yaml.SafeDumper):
    pass


def represent_string(dumper: yaml.SafeDumper, value: str) -> yaml.nodes.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


RawDumper.add_representer(str, represent_string)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench-root", type=Path, default=DEFAULT_BENCH_ROOT)
    parser.add_argument("--so-root", type=Path, action="append", default=[])
    parser.add_argument("--gh-root", type=Path, action="append", default=[])
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)

    bench_root = args.bench_root.resolve()
    so_roots = [path.resolve() for path in (args.so_root or DEFAULT_SO_ROOTS) if path.exists()]
    gh_roots = [path.resolve() for path in (args.gh_root or DEFAULT_GH_ROOTS) if path.exists()]

    records = collect_records(bench_root, so_roots, gh_roots)
    index = build_index(records)
    print_summary(index)

    if not args.apply:
        print("dry_run: true")
        return 0

    raw_root = bench_root / "raw"
    write_records(raw_root, records)
    (raw_root / "index.yaml").write_text(dump_yaml(index), encoding="utf-8")
    return 0


def collect_records(bench_root: Path, so_roots: list[Path], gh_roots: list[Path]) -> list[dict[str, Any]]:
    benchmark_cases = load_benchmark_cases(bench_root)
    verified = load_verified_statuses()
    chosen: dict[tuple[str, str], dict[str, Any]] = {}

    existing_raw = bench_root / "raw"
    if existing_raw.exists():
        so_roots = [existing_raw / "so", *so_roots]
        gh_roots = [existing_raw / "gh", *gh_roots]

    for root in so_roots:
        for path in sorted(root.glob("stackoverflow-*.yaml")):
            raw = load_yaml(path)
            raw_id = str(raw.get("case_id") or path.stem)
            record = build_record(raw_id, "stackoverflow", path, raw, benchmark_cases, verified)
            keep_better(chosen, ("so", raw_id), record)

    for root in gh_roots:
        for path in sorted(root.glob("*.yaml")):
            if path.name == "index.yaml":
                continue
            raw = load_yaml(path)
            raw_id = str(raw.get("case_id") or raw.get("raw_id") or path.stem)
            source_kind = infer_github_source_kind(raw_id, raw)
            record = build_record(raw_id, source_kind, path, raw, benchmark_cases, verified)
            keep_better(chosen, ("gh", raw_id), record)

    for raw_id, status in verified.items():
        if raw_id.startswith("stackoverflow-"):
            key = ("so", raw_id)
            source_kind = "stackoverflow"
        elif raw_id.startswith("github-"):
            key = ("gh", raw_id)
            source_kind = "github_issue"
        else:
            continue
        if key in chosen:
            continue
        raw = raw_from_status(raw_id, source_kind, status)
        artifact_path = Path(status.get("artifact_path") or ".") / "verification_status.txt"
        record = build_record(raw_id, source_kind, artifact_path, raw, benchmark_cases, verified)
        keep_better(chosen, key, record)

    return sorted(chosen.values(), key=lambda item: (raw_bucket(item["source_kind"]), item["raw_id"]))


def load_benchmark_cases(bench_root: Path) -> dict[str, dict[str, Any]]:
    manifest_path = bench_root / "manifest.yaml"
    if not manifest_path.exists():
        return {}
    manifest = load_yaml(manifest_path)
    result: dict[str, dict[str, Any]] = {}
    for entry in manifest.get("cases") or []:
        if isinstance(entry, dict) and isinstance(entry.get("case_id"), str):
            result[entry["case_id"]] = entry
    return result


def load_verified_statuses() -> dict[str, dict[str, Any]]:
    statuses: dict[str, dict[str, Any]] = {}
    for root in VERIFIED_ROOTS:
        if not root.exists():
            continue
        for status_path in sorted(root.glob("*/verification_status.txt")):
            case_id = status_path.parent.name
            status = parse_status(status_path)
            status.setdefault("case_id", case_id)
            status["artifact_path"] = relpath(status_path.parent)
            log_path = status_path.parent / "verifier_log_captured.txt"
            if log_path.exists():
                status["verifier_log_captured"] = "yes"
                parsed = parse_verifier_log(log_path.read_text(encoding="utf-8", errors="replace"))
                status["parsed_log_quality"] = parsed.log_quality
                if parsed.terminal_error:
                    status.setdefault("captured_error", parsed.terminal_error)
                if parsed.rejected_insn_idx is not None:
                    status["parsed_rejected_insn_idx"] = str(parsed.rejected_insn_idx)
            if case_id in statuses and status_preference(statuses[case_id]) >= status_preference(status):
                continue
            statuses[case_id] = status
    return statuses


def status_preference(status: dict[str, str]) -> int:
    if status.get("compile_ok") == "True" and status.get("verifier_status") == "rejected":
        return 3
    if status.get("verifier_status") == "rejected":
        return 2
    if status.get("artifact_status") == "failed" or status.get("verifier_status"):
        return 1
    return 0


def build_record(
    raw_id: str,
    source_kind: str,
    raw_path: Path,
    raw: dict[str, Any],
    benchmark_cases: dict[str, dict[str, Any]],
    verified: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    source = source_summary(raw_id, source_kind, raw)
    content = content_summary(raw)
    reproduction = reproduction_summary(raw_id, source_kind, raw, benchmark_cases, verified)
    original_path = relpath(raw_path)
    payload = normalized_raw_payload(raw_id, source_kind, raw)
    if raw.get("schema_version") == "bpfix.raw_external/v1":
        collector = raw.get("collector") if isinstance(raw.get("collector"), dict) else {}
        original_path = collector.get("original_path") or original_path
    current_path = f"bpfix-bench/raw/{raw_bucket(source_kind)}/{raw_id}.yaml"
    return {
        "schema_version": "bpfix.raw_external/v1",
        "raw_id": raw_id,
        "source_kind": source_kind,
        "source": source,
        "collector": {
            "original_path": current_path,
            "synced_at": date.today().isoformat(),
        },
        "content": content,
        "reproduction": reproduction,
        "raw": payload,
    }


def source_summary(raw_id: str, source_kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema_version") == "bpfix.raw_external/v1":
        existing_source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
        return {
            "url": existing_source.get("url"),
            "title": existing_source.get("title"),
            "repository": existing_source.get("repository"),
            "commit": existing_source.get("commit"),
            "collected_at": existing_source.get("collected_at"),
        }
    if source_kind == "stackoverflow":
        question = raw.get("question") if isinstance(raw.get("question"), dict) else {}
        question_id = question.get("question_id") or raw_id.rsplit("-", 1)[-1]
        return {
            "url": question.get("url") or f"https://stackoverflow.com/questions/{question_id}",
            "title": question.get("title"),
            "repository": None,
            "commit": None,
            "collected_at": raw.get("collected_at"),
        }
    if source_kind == "github_issue":
        issue = raw.get("issue") if isinstance(raw.get("issue"), dict) else {}
        repository = issue.get("repository")
        return {
            "url": issue.get("url"),
            "title": issue.get("title"),
            "repository": f"https://github.com/{repository}" if repository else None,
            "commit": None,
            "collected_at": raw.get("collected_at"),
        }
    repository = raw.get("repository")
    commit = raw.get("commit_hash") or raw.get("original_commit")
    return {
        "url": commit_url(repository, commit),
        "title": raw.get("commit_message") or raw.get("original_commit_message"),
        "repository": repository,
        "commit": commit,
        "collected_at": raw.get("collected_at"),
    }


def content_summary(raw: dict[str, Any]) -> dict[str, Any]:
    raw = raw_payload(raw)
    verifier_log = raw.get("verifier_log") or raw.get("original_verifier_log")
    source_snippets = raw.get("source_snippets")
    if not isinstance(source_snippets, list):
        source_snippets = []
    return {
        "has_verifier_log": bool(verifier_log),
        "verifier_log_block_count": count_log_blocks(verifier_log),
        "source_snippet_count": len(source_snippets),
        "has_buggy_code": bool(raw.get("buggy_code")),
        "has_fixed_code": bool(raw.get("fixed_code") or raw.get("fix")),
        "has_fix_description": bool(raw.get("fix_description") or raw.get("fix")),
    }


def reproduction_summary(
    raw_id: str,
    source_kind: str,
    raw: dict[str, Any],
    benchmark_cases: dict[str, dict[str, Any]],
    verified: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    benchmark_entry = benchmark_cases.get(raw_id)
    status = verified.get(raw_id)
    if benchmark_entry:
        return {
            "status": "replay_valid",
            "case_id": raw_id,
            "case_path": benchmark_entry.get("path"),
            "artifact_path": benchmark_entry.get("path"),
            "reason": "admitted_to_bpfix_bench_cases",
        }
    if raw.get("schema_version") == "bpfix.raw_external/v1":
        existing = raw.get("reproduction")
        if isinstance(existing, dict) and existing.get("status"):
            if existing.get("status") == "not_attempted":
                return triage_unreconstructed_raw(raw_id, source_kind, raw)
            preserved = dict(existing)
            preserved["artifact_path"] = None
            return preserved
    if status:
        verifier_status = str(status.get("verifier_status") or "").lower()
        compile_ok = str(status.get("compile_ok") or status.get("buggy_compile") or "").lower()
        artifact_status = str(status.get("artifact_status") or "").lower()
        rejected_insn_idx = status.get("parsed_rejected_insn_idx")
        if verifier_status == "rejected" and compile_ok == "true":
            if not rejected_insn_idx:
                summary_status = "replay_reject_no_rejected_insn"
                reason = "local_reconstruction_rejects_but_lacks_a_rejected_instruction_index"
            else:
                summary_status = "replay_valid_pending_import"
                reason = "local_reconstruction_rejects_but_not_in_cases"
        elif verifier_status == "accepted":
            summary_status = "attempted_accepted"
            reason = status.get("failure_reason") or "local_reconstruction_was_accepted"
        elif artifact_status == "failed":
            summary_status = "attempted_failed"
            reason = status.get("failure_reason") or "local_reconstruction_failed"
        else:
            summary_status = "attempted_unknown"
            reason = status.get("failure_reason") or verifier_status or "verification_status_unclear"
        return {
            "status": summary_status,
            "case_id": None,
            "case_path": None,
            "artifact_path": status.get("artifact_path"),
            "reason": reason,
            "verifier_status": status.get("verifier_status"),
            "captured_error": status.get("captured_error"),
            "verifier_error_match": status.get("verifier_error_match"),
        }
    return triage_unreconstructed_raw(raw_id, source_kind, raw)


def triage_unreconstructed_raw(raw_id: str, source_kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    content = content_summary(raw)
    verifier_log = raw_verifier_log_text(raw)
    parsed = parse_verifier_log(verifier_log) if verifier_log else None
    has_source = bool(content.get("source_snippet_count") or content.get("has_buggy_code"))
    has_log = bool(content.get("has_verifier_log"))
    has_parseable_reject = bool(parsed and parsed.terminal_error)

    if source_kind == "github_commit":
        return unreconstructed_summary(
            "needs_manual_reconstruction",
            "commit_diff_requires_manual_standalone_reproducer_and_local_replay",
        )
    if not has_log:
        status = "missing_verifier_log" if has_source else "missing_source"
        reason = "source_present_but_no_verifier_log" if has_source else "no_source_or_verifier_log_available"
        return unreconstructed_summary(status, reason)
    if not has_parseable_reject:
        return unreconstructed_summary(
            "out_of_scope_non_verifier",
            "external_log_does_not_contain_a_parseable_verifier_reject",
        )
    if not has_source:
        return unreconstructed_summary("missing_source", "verifier_reject_present_but_no_reproducer_source")
    return unreconstructed_summary(
        "candidate_for_replay",
        "verifier_reject_and_source_context_present_but_no_local_harness_yet",
    )


def unreconstructed_summary(status: str, reason: str) -> dict[str, Any]:
    return {
        "status": status,
        "case_id": None,
        "case_path": None,
        "artifact_path": None,
        "reason": reason,
    }


def raw_verifier_log_text(raw: dict[str, Any]) -> str:
    payload = raw_payload(raw)
    verifier_log = payload.get("verifier_log") or payload.get("original_verifier_log")
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined")
        if isinstance(combined, str):
            return combined
        blocks = verifier_log.get("blocks")
        if isinstance(blocks, list):
            return "\n".join(str(block) for block in blocks)
        return str(verifier_log)
    if isinstance(verifier_log, list):
        return "\n".join(str(block) for block in verifier_log)
    if isinstance(verifier_log, str):
        return verifier_log
    return ""


def build_index(records: list[dict[str, Any]]) -> dict[str, Any]:
    entries = []
    counts: dict[str, dict[str, int]] = {}
    for record in records:
        bucket = raw_bucket(record["source_kind"])
        status = record["reproduction"]["status"]
        counts.setdefault(bucket, {})
        counts[bucket]["total"] = counts[bucket].get("total", 0) + 1
        counts[bucket][status] = counts[bucket].get(status, 0) + 1
        counts.setdefault("all", {})
        counts["all"]["total"] = counts["all"].get("total", 0) + 1
        counts["all"][status] = counts["all"].get(status, 0) + 1
        entries.append(
            {
                "raw_id": record["raw_id"],
                "source_kind": record["source_kind"],
                "path": f"raw/{bucket}/{record['raw_id']}.yaml",
                "url": record["source"]["url"],
                "reproduction_status": status,
                "case_path": record["reproduction"].get("case_path"),
                "artifact_path": record["reproduction"].get("artifact_path"),
            }
        )
    return {
        "schema_version": "bpfix.raw_index/v1",
        "generated_at": date.today().isoformat(),
        "description": "Raw external SO/GH/commit records. Replayable verifier rejects are linked into bpfix-bench/cases.",
        "counts": counts,
        "entries": entries,
    }


def write_records(raw_root: Path, records: list[dict[str, Any]]) -> None:
    for bucket in ("so", "gh"):
        (raw_root / bucket).mkdir(parents=True, exist_ok=True)
    for record in records:
        bucket = raw_bucket(record["source_kind"])
        path = raw_root / bucket / f"{record['raw_id']}.yaml"
        path.write_text(dump_yaml(record), encoding="utf-8")


def keep_better(chosen: dict[tuple[str, str], dict[str, Any]], key: tuple[str, str], record: dict[str, Any]) -> None:
    current = chosen.get(key)
    if current is None or record_score(record) > record_score(current):
        chosen[key] = record


def record_score(record: dict[str, Any]) -> tuple[int, int, int, str]:
    content = record["content"]
    raw_text_len = len(str(record.get("raw") or ""))
    return (
        int(content.get("source_snippet_count") or 0),
        int(content.get("verifier_log_block_count") or 0),
        raw_text_len,
        str(record["collector"]["original_path"]),
    )


def count_log_blocks(value: Any) -> int:
    if isinstance(value, dict):
        blocks = value.get("blocks")
        if isinstance(blocks, list):
            return len(blocks)
        return 1 if value else 0
    if isinstance(value, list):
        return len(value)
    return 1 if value else 0


def raw_bucket(source_kind: str) -> str:
    return "so" if source_kind == "stackoverflow" else "gh"


def infer_github_source_kind(raw_id: str, raw: dict[str, Any]) -> str:
    if raw.get("schema_version") == "bpfix.raw_external/v1":
        existing_kind = raw.get("source_kind")
        if existing_kind in {"github_issue", "github_commit"}:
            return str(existing_kind)
    if raw_id.startswith("github-commit-"):
        return "github_commit"
    if raw_id.startswith("github-"):
        return "github_issue"
    return "github_commit"


def parse_status(path: Path) -> dict[str, str]:
    status: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        status[key.strip()] = value.strip()
    return status


def commit_url(repository: Any, commit: Any) -> str | None:
    if not repository or not commit:
        return None
    repo = str(repository).rstrip("/")
    return f"{repo}/commit/{commit}"


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    return data if isinstance(data, dict) else {}


def raw_payload(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema_version") != "bpfix.raw_external/v1":
        return raw
    payload = raw.get("raw")
    return payload if isinstance(payload, dict) else {}


def normalized_raw_payload(raw_id: str, source_kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    payload = dict(raw_payload(raw))
    if source_kind == "github_commit" and not payload.get("case_id"):
        payload["case_id"] = raw_id
    return payload


def raw_from_status(raw_id: str, source_kind: str, status: dict[str, str]) -> dict[str, Any]:
    source_url = status.get("source_url")
    if source_url == "<unknown>":
        source_url = None
    raw: dict[str, Any] = {
        "case_id": raw_id,
        "source": "stackoverflow" if source_kind == "stackoverflow" else "github_issues",
        "collected_at": None,
        "external_evidence": {
            "original_error": status.get("original_error"),
            "source_origin": status.get("source_origin"),
            "notes": status.get("notes"),
        },
    }
    if source_kind == "stackoverflow":
        question_id = raw_id.rsplit("-", 1)[-1]
        raw["question"] = {
            "question_id": int(question_id) if question_id.isdigit() else question_id,
            "title": None,
            "url": source_url or f"https://stackoverflow.com/questions/{question_id}",
        }
    else:
        repository, number = parse_github_id(raw_id)
        raw["issue"] = {
            "repository": repository,
            "number": number,
            "title": None,
            "url": source_url,
        }
    return raw


def parse_github_id(raw_id: str) -> tuple[str | None, int | None]:
    stem = raw_id.removeprefix("github-")
    parts = stem.rsplit("-", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        return None, None
    repo_part, number = parts
    known = {
        "aya-rs-aya": "aya-rs/aya",
        "cilium-cilium": "cilium/cilium",
        "iovisor-bcc": "iovisor/bcc",
        "orangeopensource-p4rt-ovs": "Orange-OpenSource/p4rt-ovs",
        "facebookincubator-katran": "facebookincubator/katran",
    }
    return known.get(repo_part), int(number)


def dump_yaml(data: dict[str, Any]) -> str:
    return yaml.dump(data, Dumper=RawDumper, sort_keys=False, allow_unicode=False).rstrip() + "\n"


def relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def print_summary(index: dict[str, Any]) -> None:
    counts = index.get("counts") or {}
    for bucket in ("so", "gh", "all"):
        bucket_counts = counts.get(bucket) or {}
        if not bucket_counts:
            continue
        parts = [f"{key}={value}" for key, value in sorted(bucket_counts.items())]
        print(f"{bucket}: " + " ".join(parts))


if __name__ == "__main__":
    raise SystemExit(main())
