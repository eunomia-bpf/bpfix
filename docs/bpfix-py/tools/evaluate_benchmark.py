#!/usr/bin/env python3
"""Run diagnostic baselines on freshly replayed bpfix-bench verifier logs."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

ARCHIVE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ARCHIVE_ROOT.parents[1]
if str(ARCHIVE_ROOT) not in sys.path:
    sys.path.insert(0, str(ARCHIVE_ROOT))

from bpfix.baseline import generate_baseline_diagnostic
from bpfix.extractor.engine.cfg_builder import build_cfg
from bpfix.extractor.engine.monitor import CarrierBoundPredicate, TraceMonitor, monitor_carriers
from bpfix.extractor.engine.opcode_safety import (
    OpcodeConditionPredicate,
    discover_compatible_carriers,
    evaluate_condition,
    find_violated_condition,
    infer_conditions_from_error_insn,
    infer_safety_schemas,
    instantiate_primary_carrier,
    instantiate_schema,
)
from bpfix.extractor.engine.slicer import backward_slice
from bpfix.extractor.log_parser import parse_log
from bpfix.extractor.pipeline import (
    _STRUCTURAL_TAXONOMY_BY_ERROR_ID,
    _build_proof_events,
    _ensure_rejected_span,
    aggregate_atom_classes,
    classify_atom,
    compute_forward_dominators,
)
from bpfix.extractor.pipeline import generate_diagnostic
from bpfix.extractor.source_correlator import correlate_to_source
from bpfix.extractor.trace_parser import parse_trace
from tools.replay_case import replay_case


DEFAULT_BENCHMARK_ROOT = PROJECT_ROOT / "bpfix-bench"
DEFAULT_RESULTS_PATH = PROJECT_ROOT / "docs" / "tmp" / "benchmark-eval-results.json"
METHOD_KEYS = ("bpfix", "baseline", "ablation_a", "ablation_b", "ablation_c")
GENERATED_ARTIFACT_NAMES = {
    "prog.o",
    "replay-verifier.log",
    "verifier.log",
    "selftest_prog_loader",
    "verifier_load_result.json",
    "replay_load_result.json",
}


@dataclass(slots=True)
class CaseContext:
    case_id: str
    case_dir: Path
    source_kind: str
    verifier_log: str
    label: dict[str, Any]
    parsed_log: Any
    parsed_trace: Any
    instructions: list[Any]
    error_insn: Any | None
    structural_taxonomy: str | None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK_ROOT)
    parser.add_argument("--results-path", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument(
        "--methods",
        default=",".join(METHOD_KEYS),
        help="Comma-separated methods: bpfix,baseline,ablation_a,ablation_b,ablation_c.",
    )
    parser.add_argument("--timeout-sec", type=int, default=60, help="Per-command replay timeout.")
    parser.add_argument("--limit", type=int, default=None, help="Optional case limit for quick checks.")
    parser.add_argument("--case-id", action="append", default=[], help="Optional case_id filter.")
    parser.add_argument(
        "--source-kind",
        action="append",
        choices=("stackoverflow", "github_issue", "github_commit", "kernel_selftest"),
        default=[],
        help="Optional source-kind filter.",
    )
    parser.add_argument("--print-every", type=int, default=25, help="Progress interval; 0 disables.")
    parser.add_argument("--fail-fast", action="store_true", help="Stop at the first replay/method failure.")
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep replay .o/log files; by default they are deleted after each case.",
    )
    return parser.parse_args(argv)


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def parse_methods(methods_text: str) -> list[str]:
    methods = [item.strip() for item in methods_text.split(",") if item.strip()]
    unknown = sorted(set(methods) - set(METHODS))
    if unknown:
        raise ValueError(f"unknown methods: {', '.join(unknown)}")
    return methods


def iter_manifest_entries(
    benchmark_root: Path,
    *,
    case_ids: set[str] | None,
    source_kinds: set[str] | None,
    limit: int | None,
) -> list[dict[str, Any]]:
    manifest = load_yaml_mapping(benchmark_root / "manifest.yaml")
    entries = manifest.get("cases")
    if not isinstance(entries, list):
        raise ValueError("manifest.cases must be a list")

    rows = [entry for entry in entries if isinstance(entry, dict) and entry.get("case_id")]
    if case_ids:
        rows = [entry for entry in rows if str(entry.get("case_id")) in case_ids]
    if source_kinds:
        rows = [entry for entry in rows if str(entry.get("source_kind")) in source_kinds]
    if limit is not None:
        rows = rows[:limit]
    return rows


def replay_and_validate_case(case_dir: Path, case_data: dict[str, Any], timeout_sec: int) -> tuple[str | None, dict[str, Any]]:
    replay = replay_case(case_dir, case_data, timeout_sec=timeout_sec)
    capture = case_data.get("capture") if isinstance(case_data.get("capture"), dict) else {}
    fresh = {
        "terminal_error": replay.parsed_log.terminal_error,
        "rejected_insn_idx": replay.parsed_log.rejected_insn_idx,
        "log_quality": replay.parsed_log.log_quality,
        "source": replay.parsed_log.source,
    }
    errors: list[str] = []

    if replay.build.timed_out:
        errors.append("build command timed out")
    elif replay.build.returncode != 0:
        errors.append(f"build command failed with exit code {replay.build.returncode}")
    if replay.load.timed_out:
        errors.append("load command timed out")
    elif replay.load.returncode == 0:
        errors.append("load command succeeded; expected verifier reject")

    expected_terminal = capture.get("terminal_error")
    expected_idx = capture.get("rejected_insn_idx")
    expected_quality = capture.get("log_quality")
    if not replay.verifier_log_captured:
        errors.append("fresh replay did not capture a verifier log")
    if not replay.parsed_log.terminal_error:
        errors.append("fresh replay did not produce a parseable terminal error")
    elif expected_terminal != replay.parsed_log.terminal_error:
        errors.append(
            f"terminal_error mismatch: expected {expected_terminal!r}, got {replay.parsed_log.terminal_error!r}"
        )
    if replay.parsed_log.rejected_insn_idx is None:
        errors.append("fresh replay did not produce a rejected instruction index")
    elif expected_idx != replay.parsed_log.rejected_insn_idx:
        errors.append(
            f"rejected_insn_idx mismatch: expected {expected_idx!r}, got {replay.parsed_log.rejected_insn_idx!r}"
        )
    if expected_quality and expected_quality != replay.parsed_log.log_quality:
        errors.append(
            f"log_quality mismatch: expected {expected_quality!r}, got {replay.parsed_log.log_quality!r}"
        )

    report = {
        "ok": not errors,
        "errors": errors,
        "fresh": fresh,
        "build_returncode": replay.build.returncode,
        "load_returncode": replay.load.returncode,
    }
    return replay.verifier_log_captured, report


def load_context(entry: dict[str, Any], verifier_log: str, case_dir: Path, case_data: dict[str, Any]) -> CaseContext:
    parsed_log = parse_log(verifier_log)
    parsed_trace = parse_trace(verifier_log)
    instructions = list(getattr(parsed_trace, "instructions", []))
    error_insn = next((insn for insn in instructions if getattr(insn, "is_error", False)), None)
    label = case_data.get("label")
    if not isinstance(label, dict):
        label = {}
    return CaseContext(
        case_id=str(entry["case_id"]),
        case_dir=case_dir,
        source_kind=str(entry.get("source_kind") or ""),
        verifier_log=verifier_log,
        label=label,
        parsed_log=parsed_log,
        parsed_trace=parsed_trace,
        instructions=instructions,
        error_insn=error_insn,
        structural_taxonomy=_STRUCTURAL_TAXONOMY_BY_ERROR_ID.get(parsed_log.error_id),
    )


def method_error_id(parsed_log: Any) -> str:
    error_id = getattr(parsed_log, "error_id", None)
    return str(error_id) if error_id else "BPFIX-UNKNOWN"


def metadata(json_data: dict[str, Any]) -> dict[str, Any]:
    raw_metadata = json_data.get("metadata")
    return raw_metadata if isinstance(raw_metadata, dict) else {}


def count_spans(json_data: dict[str, Any]) -> int:
    spans = json_data.get("spans")
    if isinstance(spans, list):
        return len(spans)
    proof_spans = metadata(json_data).get("proof_spans")
    return len(proof_spans) if isinstance(proof_spans, list) else 0


def normalize_taxonomy(json_data: dict[str, Any]) -> str:
    taxonomy = json_data.get("taxonomy_class") or json_data.get("failure_class")
    return str(taxonomy) if taxonomy else "unknown"


def label_comparison(result: dict[str, Any], label: dict[str, Any]) -> dict[str, Any]:
    expected_error_id = label.get("error_id")
    expected_taxonomy = label.get("taxonomy_class")
    return {
        "expected_error_id": expected_error_id,
        "expected_taxonomy": expected_taxonomy,
        "error_id_match": bool(expected_error_id and result.get("error_id") == expected_error_id),
        "taxonomy_match": bool(expected_taxonomy and result.get("taxonomy") == expected_taxonomy),
    }


def bpfix_result(ctx: CaseContext) -> dict[str, Any]:
    output = generate_diagnostic(ctx.verifier_log)
    json_data = output.json_data if isinstance(output.json_data, dict) else {}
    meta = metadata(json_data)
    active_atoms = meta.get("active_atoms")
    if not isinstance(active_atoms, list):
        active_atoms = []
    return {
        "error_id": str(json_data.get("error_id") or method_error_id(ctx.parsed_log)),
        "taxonomy": normalize_taxonomy(json_data),
        "proof_status": str(meta.get("proof_status") or "unknown"),
        "spans": count_spans(json_data),
        "cross_class": meta.get("cross_analysis_class"),
        "active_atom_classes": [
            str(atom.get("classification"))
            for atom in active_atoms
            if isinstance(atom, dict) and atom.get("classification")
        ],
    }


def baseline_result(ctx: CaseContext) -> dict[str, Any]:
    output = generate_baseline_diagnostic(ctx.verifier_log)
    json_data = output.json_data if isinstance(output.json_data, dict) else {}
    meta = metadata(json_data)
    return {
        "error_id": str(json_data.get("error_id") or method_error_id(ctx.parsed_log)),
        "taxonomy": normalize_taxonomy(json_data),
        "proof_status": str(meta.get("proof_status") or "unknown"),
        "spans": count_spans(json_data),
    }


def proof_status_without_predicate(ctx: CaseContext) -> str:
    return "never_established" if ctx.error_insn is not None else "unknown"


def monitor_none(ctx: CaseContext) -> Any:
    return TraceMonitor().monitor(None, ctx.instructions)


def span_count_from_monitor(ctx: CaseContext, predicate: Any, monitor_result: Any) -> int:
    proof_events = _build_proof_events(monitor_result=monitor_result, predicate=predicate, parsed_trace=ctx.parsed_trace)
    spans = correlate_to_source(ctx.parsed_trace, proof_events)
    spans = _ensure_rejected_span(spans, ctx.parsed_trace, ctx.parsed_log)
    return len(spans)


def structural_result(ctx: CaseContext) -> dict[str, Any]:
    monitor_result = monitor_none(ctx)
    return {
        "error_id": method_error_id(ctx.parsed_log),
        "taxonomy": str(ctx.structural_taxonomy),
        "proof_status": "unknown",
        "spans": span_count_from_monitor(ctx, None, monitor_result),
    }


def ablation_a_result(ctx: CaseContext) -> dict[str, Any]:
    if ctx.structural_taxonomy is not None:
        return structural_result(ctx)
    predicate = None
    proof_status = proof_status_without_predicate(ctx)
    monitor_result = monitor_none(ctx)
    if ctx.error_insn is not None:
        conditions = infer_conditions_from_error_insn(ctx.error_insn)
        violated = find_violated_condition(ctx.error_insn, conditions)
        if violated is not None:
            predicate = OpcodeConditionPredicate(violated)
            monitor_result = TraceMonitor().monitor(predicate, ctx.instructions)
            proof_status = monitor_result.proof_status
    taxonomy = "lowering_artifact" if proof_status == "established_then_lost" else "source_bug"
    return {
        "error_id": method_error_id(ctx.parsed_log),
        "taxonomy": taxonomy,
        "proof_status": proof_status,
        "spans": span_count_from_monitor(ctx, predicate, monitor_result),
    }


def select_primary_monitor_for_no_slice(ctx: CaseContext) -> tuple[Any, Any, str]:
    selected_predicate = None
    selected_monitor_result = monitor_none(ctx)
    selected_proof_status = proof_status_without_predicate(ctx)
    if ctx.error_insn is None:
        return selected_predicate, selected_monitor_result, selected_proof_status

    lowering_candidate: tuple[Any, Any] | None = None
    fallback_candidate: tuple[Any, Any] | None = None
    for schema in infer_safety_schemas(ctx.error_insn):
        primary = instantiate_primary_carrier(schema, ctx.error_insn)
        if primary is None:
            continue
        condition = instantiate_schema(schema, primary)
        if evaluate_condition(condition, ctx.error_insn.pre_state) == "satisfied":
            continue
        predicate = CarrierBoundPredicate(condition, primary)
        monitor_result = TraceMonitor().monitor(predicate, ctx.instructions)
        carriers = discover_compatible_carriers(schema, primary, ctx.error_insn.pre_state)
        lifecycles = monitor_carriers(schema, carriers, ctx.instructions)
        primary_lifecycle = lifecycles.get(primary.register)
        any_establish = any(
            any(event.kind == "establish" for event in lifecycle.events)
            for lifecycle in lifecycles.values()
        )
        primary_loss = bool(primary_lifecycle and primary_lifecycle.loss_site is not None)
        if fallback_candidate is None:
            fallback_candidate = (predicate, monitor_result)
        if lowering_candidate is None and any_establish and not primary_loss:
            lowering_candidate = (predicate, monitor_result)

    chosen = lowering_candidate or fallback_candidate
    if chosen is None:
        return selected_predicate, selected_monitor_result, selected_proof_status
    selected_predicate, selected_monitor_result = chosen
    return selected_predicate, selected_monitor_result, selected_monitor_result.proof_status


def ablation_b_taxonomy(ctx: CaseContext) -> str:
    if ctx.error_insn is None:
        return "source_bug"
    for schema in infer_safety_schemas(ctx.error_insn):
        primary = instantiate_primary_carrier(schema, ctx.error_insn)
        if primary is None:
            continue
        condition = instantiate_schema(schema, primary)
        if evaluate_condition(condition, ctx.error_insn.pre_state) == "satisfied":
            continue
        carriers = discover_compatible_carriers(schema, primary, ctx.error_insn.pre_state)
        lifecycles = monitor_carriers(schema, carriers, ctx.instructions)
        primary_lifecycle = lifecycles.get(primary.register)
        any_establish = any(
            any(event.kind == "establish" for event in lifecycle.events)
            for lifecycle in lifecycles.values()
        )
        primary_loss = bool(primary_lifecycle and primary_lifecycle.loss_site is not None)
        if any_establish and not primary_loss:
            return "lowering_artifact"
    return "source_bug"


def ablation_b_result(ctx: CaseContext) -> dict[str, Any]:
    if ctx.structural_taxonomy is not None:
        return structural_result(ctx)
    predicate, monitor_result, proof_status = select_primary_monitor_for_no_slice(ctx)
    return {
        "error_id": method_error_id(ctx.parsed_log),
        "taxonomy": ablation_b_taxonomy(ctx),
        "proof_status": proof_status,
        "spans": span_count_from_monitor(ctx, predicate, monitor_result),
    }


def select_primary_monitor_for_no_carrier(ctx: CaseContext) -> tuple[Any, Any, str]:
    selected_predicate = None
    selected_monitor_result = monitor_none(ctx)
    selected_proof_status = proof_status_without_predicate(ctx)
    if ctx.error_insn is None:
        return selected_predicate, selected_monitor_result, selected_proof_status

    cfg = build_cfg(ctx.instructions) if ctx.instructions else None
    dominators = compute_forward_dominators(cfg) if cfg is not None else {}
    lowering_candidate: tuple[Any, Any] | None = None
    fallback_candidate: tuple[Any, Any] | None = None
    for schema in infer_safety_schemas(ctx.error_insn):
        primary = instantiate_primary_carrier(schema, ctx.error_insn)
        if primary is None:
            continue
        condition = instantiate_schema(schema, primary)
        reject_evaluation = evaluate_condition(condition, ctx.error_insn.pre_state)
        if reject_evaluation == "satisfied":
            continue
        predicate = CarrierBoundPredicate(condition, primary)
        lifecycle = TraceMonitor().monitor_events(predicate, ctx.instructions)
        bslice = backward_slice(ctx.instructions, criterion_insn=ctx.error_insn.insn_idx, criterion_register=primary.register, cfg=cfg)
        atom = classify_atom(
            schema,
            ctx.error_insn,
            ctx.instructions,
            cfg,
            dominators,
            primary=primary,
            monitoring={primary.register: lifecycle},
            bslice=bslice,
            reject_evaluation=reject_evaluation,
        )
        monitor_result = TraceMonitor().monitor(predicate, ctx.instructions)
        if fallback_candidate is None:
            fallback_candidate = (predicate, monitor_result)
        if lowering_candidate is None and atom.classification in {"lowering_artifact", "established_then_lost"}:
            lowering_candidate = (predicate, monitor_result)

    chosen = lowering_candidate or fallback_candidate
    if chosen is None:
        return selected_predicate, selected_monitor_result, selected_proof_status
    selected_predicate, selected_monitor_result = chosen
    return selected_predicate, selected_monitor_result, selected_monitor_result.proof_status


def ablation_c_taxonomy(ctx: CaseContext) -> str:
    if ctx.error_insn is None:
        return "source_bug"
    cfg = build_cfg(ctx.instructions) if ctx.instructions else None
    dominators = compute_forward_dominators(cfg) if cfg is not None else {}
    atom_classes: list[str] = []
    for schema in infer_safety_schemas(ctx.error_insn):
        primary = instantiate_primary_carrier(schema, ctx.error_insn)
        if primary is None:
            atom_classes.append("ambiguous")
            continue
        condition = instantiate_schema(schema, primary)
        reject_evaluation = evaluate_condition(condition, ctx.error_insn.pre_state)
        if reject_evaluation == "satisfied":
            atom_classes.append("inactive")
            continue
        predicate = CarrierBoundPredicate(condition, primary)
        lifecycle = TraceMonitor().monitor_events(predicate, ctx.instructions)
        bslice = backward_slice(ctx.instructions, criterion_insn=ctx.error_insn.insn_idx, criterion_register=primary.register, cfg=cfg)
        atom = classify_atom(
            schema,
            ctx.error_insn,
            ctx.instructions,
            cfg,
            dominators,
            primary=primary,
            monitoring={primary.register: lifecycle},
            bslice=bslice,
            reject_evaluation=reject_evaluation,
        )
        atom_classes.append(atom.classification)
    return "lowering_artifact" if aggregate_atom_classes(atom_classes) in {"lowering_artifact", "established_then_lost"} else "source_bug"


def ablation_c_result(ctx: CaseContext) -> dict[str, Any]:
    if ctx.structural_taxonomy is not None:
        return structural_result(ctx)
    predicate, monitor_result, proof_status = select_primary_monitor_for_no_carrier(ctx)
    return {
        "error_id": method_error_id(ctx.parsed_log),
        "taxonomy": ablation_c_taxonomy(ctx),
        "proof_status": proof_status,
        "spans": span_count_from_monitor(ctx, predicate, monitor_result),
    }


METHODS: dict[str, Callable[[CaseContext], dict[str, Any]]] = {
    "bpfix": bpfix_result,
    "baseline": baseline_result,
    "ablation_a": ablation_a_result,
    "ablation_b": ablation_b_result,
    "ablation_c": ablation_c_result,
}


def run_method(method: str, ctx: CaseContext, *, fail_fast: bool) -> dict[str, Any]:
    try:
        result = METHODS[method](ctx)
        result["ok"] = True
        result["label"] = label_comparison(result, ctx.label)
        return result
    except Exception as exc:  # noqa: BLE001
        if fail_fast:
            raise
        return {
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(limit=8),
            "label": label_comparison({}, ctx.label),
        }


def cleanup_case_artifacts(case_dir: Path) -> None:
    for path in case_dir.iterdir():
        if path.is_file() and (path.name in GENERATED_ARTIFACT_NAMES or path.suffix == ".o"):
            path.unlink(missing_ok=True)


def evaluate_entry(
    benchmark_root: Path,
    entry: dict[str, Any],
    methods: list[str],
    args: argparse.Namespace,
) -> dict[str, Any]:
    case_id = str(entry["case_id"])
    case_dir = benchmark_root / str(entry["path"])
    case_data = load_yaml_mapping(case_dir / "case.yaml")
    row: dict[str, Any] = {
        "case_id": case_id,
        "source_kind": str(entry.get("source_kind") or ""),
        "case_path": str(case_dir.relative_to(PROJECT_ROOT)),
        "replay": {},
    }
    try:
        verifier_log, replay_report = replay_and_validate_case(case_dir, case_data, args.timeout_sec)
        row["replay"] = replay_report
        if not replay_report["ok"]:
            if args.fail_fast:
                raise RuntimeError(f"{case_id} replay failed: {replay_report['errors']}")
            return row
        if verifier_log is None:
            raise RuntimeError(f"{case_id} replay did not return a verifier log")
        ctx = load_context(entry, verifier_log, case_dir, case_data)
        for method in methods:
            row[method] = run_method(method, ctx, fail_fast=args.fail_fast)
        return row
    finally:
        if not args.keep_artifacts:
            cleanup_case_artifacts(case_dir)


def summarize(cases: list[dict[str, Any]], methods: list[str]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "total_cases": len(cases),
        "source_kind_counts": dict(Counter(str(row.get("source_kind")) for row in cases)),
        "replay": {
            "passed": sum(1 for row in cases if isinstance(row.get("replay"), dict) and row["replay"].get("ok")),
            "failed": sum(1 for row in cases if not (isinstance(row.get("replay"), dict) and row["replay"].get("ok"))),
        },
        "methods": {},
    }
    for method in methods:
        ok_rows = [row for row in cases if isinstance(row.get(method), dict) and row[method].get("ok")]
        labeled_error = [row for row in ok_rows if row[method]["label"].get("expected_error_id")]
        labeled_taxonomy = [row for row in ok_rows if row[method]["label"].get("expected_taxonomy")]
        summary["methods"][method] = {
            "ok": len(ok_rows),
            "failed": len(cases) - len(ok_rows),
            "taxonomy_counts": dict(Counter(str(row[method].get("taxonomy")) for row in ok_rows)),
            "error_id_counts": dict(Counter(str(row[method].get("error_id")) for row in ok_rows)),
            "proof_status_counts": dict(Counter(str(row[method].get("proof_status")) for row in ok_rows)),
            "error_id_accuracy": (
                sum(1 for row in labeled_error if row[method]["label"].get("error_id_match")) / len(labeled_error)
                if labeled_error
                else None
            ),
            "taxonomy_accuracy": (
                sum(1 for row in labeled_taxonomy if row[method]["label"].get("taxonomy_match")) / len(labeled_taxonomy)
                if labeled_taxonomy
                else None
            ),
        }
    return summary


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    benchmark_root = args.benchmark.resolve()
    methods = parse_methods(args.methods)
    entries = iter_manifest_entries(
        benchmark_root,
        case_ids=set(args.case_id) if args.case_id else None,
        source_kinds=set(args.source_kind) if args.source_kind else None,
        limit=args.limit,
    )
    cases: list[dict[str, Any]] = []
    for index, entry in enumerate(entries, start=1):
        cases.append(evaluate_entry(benchmark_root, entry, methods, args))
        if args.print_every > 0 and (index % args.print_every == 0 or index == len(entries)):
            print(f"[benchmark-eval] processed {index}/{len(entries)}", file=sys.stderr)
    payload = {
        "schema_version": "bpfix.benchmark_eval/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_root": str(benchmark_root),
        "input_policy": "fresh local replay logs from bpfix-bench/cases only",
        "methods": methods,
        "summary": summarize(cases, methods),
        "cases": cases,
    }
    payload["valid"] = payload["summary"]["replay"]["failed"] == 0 and all(
        payload["summary"]["methods"][method]["failed"] == 0 for method in methods
    )
    return payload


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    payload = build_payload(args)
    args.results_path.parent.mkdir(parents=True, exist_ok=True)
    args.results_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {args.results_path}")
    return 0 if payload["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
