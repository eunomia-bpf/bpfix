#!/usr/bin/env python3
"""Evaluate BPFix diagnostics against benchmark labels.

This is a label-proxy evaluation, not a user study.  It compares BPFix's
full-log output with a terminal-message-only dictionary baseline on metrics that
can be computed from checked-in benchmark labels.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable

import yaml


TOOLS_DIR = pathlib.Path(__file__).resolve().parents[2] / "bpfix-bench" / "tools"
sys.path.insert(0, str(TOOLS_DIR))
from benchmark_metadata import with_case_defaults  # noqa: E402


TAXONOMY_CLASSES = [
    "source_bug",
    "lowering_artifact",
    "environment_or_configuration",
    "verifier_false_positive",
    "verifier_limit",
]

FALLBACK_ERROR_IDS = {"BPFIX-UNKNOWN", "BPFIX-E000", "BPFIX-E099"}


@dataclass
class Prediction:
    error_id: str
    failure_class: str
    action: str
    prose_action: str
    primary_span: bool
    related_spans: int
    pc_candidates: list[int]
    analysis_error: str | None = None
    object_requested: bool = False
    object_programs: int = 0
    object_site_count: int = 0
    object_state_site_count: int = 0
    object_attach_errors: int = 0
    object_analysis_error: str | None = None
    duration_ms: float = 0.0


@dataclass
class Row:
    case_id: str
    source_kind: str
    taxonomy: str
    label_error_id: str
    label_action: str
    root_pc: int | None
    confidence: str
    bpfix: Prediction
    terminal: Prediction


def terminal_dictionary(message: str) -> Prediction:
    lower = message.lower()
    if any(
        marker in lower
        for marker in [
            "bpf program is too large",
            "combined stack size",
            "too many states",
            "complexity",
            "loop is not bounded",
            "processed 1000001 insn",
        ]
    ):
        error_id = "BPFIX-E018"
        failure_class = "verifier_limit"
    elif any(
        marker in lower
        for marker in [
            "program of this type cannot use helper",
            "cannot use helper",
            "helper call is not allowed",
            "calling kernel function",
            "jit does not support",
            "missing btf",
            "invalid bpf_context access",
            "unknown opcode",
            "expected=map_ptr",
            "unknown func",
            "permission denied",
        ]
    ):
        error_id = "BPFIX-E009"
        failure_class = "environment_or_configuration"
    elif "dynptr" in lower:
        error_id = "BPFIX-E012"
        failure_class = "source_bug"
    elif "unreleased reference" in lower or "reference has not" in lower:
        error_id = "BPFIX-E004"
        failure_class = "source_bug"
    elif (
        "invalid read from stack" in lower
        or "uninitialized" in lower
        or "r0 !read_ok" in lower
    ):
        error_id = "BPFIX-E003"
        failure_class = "source_bug"
    elif (
        "map_value_or_null" in lower
        or "ptr_or_null" in lower
        or "possibly null" in lower
    ):
        error_id = "BPFIX-E002"
        failure_class = "source_bug"
    elif "invalid access to packet" in lower or "outside of the packet" in lower:
        error_id = "BPFIX-E001"
        failure_class = "source_bug"
    elif any(
        marker in lower
        for marker in [
            "unbounded",
            "min value is negative",
            "out of bounds",
            "invalid access to map value",
            "invalid zero-sized",
            "makes pkt pointer",
            "outside of allowed memory range",
            "invalid variable-offset",
        ]
    ):
        error_id = "BPFIX-E005"
        failure_class = "source_bug"
    elif "expected pointer" in lower or "invalid mem access 'scalar'" in lower:
        error_id = "BPFIX-E006"
        failure_class = "source_bug"
    else:
        error_id = "BPFIX-UNKNOWN"
        failure_class = "source_bug"

    action = terminal_action(message, failure_class)
    return Prediction(
        error_id=error_id,
        failure_class=failure_class,
        action=action,
        prose_action=action,
        primary_span=False,
        related_spans=0,
        pc_candidates=[],
    )


def terminal_action(message: str, failure_class: str) -> str:
    lower = message.lower()
    if failure_class == "environment_or_configuration":
        return "environment"
    if failure_class == "verifier_limit":
        return "budget"
    if "null" in lower:
        return "null"
    if "reference" in lower:
        return "release"
    if "stack" in lower or "uninitialized" in lower or "read_ok" in lower:
        return "initialize"
    if (
        "bounds" in lower
        or "packet" in lower
        or "map value" in lower
        or "range" in lower
        or "out of bounds" in lower
    ):
        return "bounds"
    if "scalar" in lower or "pointer" in lower:
        return "provenance"
    return "unspecified"


def label_action(label: dict) -> str:
    taxonomy = label.get("taxonomy_class")
    fix_type = (label.get("fix_type") or "").lower()
    tags = " ".join(label.get("mechanism_tags") or []).lower()

    if (
        "sleepability" in tags
        or "context_access" in tags
        or fix_type in {"use_correct_context", "avoid_wide_context_access"}
    ):
        return "context"
    if (
        "stack_bounds" in tags
        or "large_stack_object" in tags
        or fix_type
        in {
            "add_l2_header_presence_guard",
            "map_definition_fix",
            "move_to_map_storage",
        }
    ):
        return "bounds"
    if (
        taxonomy == "source_bug"
        and fix_type == "reorder"
        and "verifier_range_precision" not in tags
        and "packet_bounds" not in tags
        and "scalar_range" not in tags
    ):
        return "protocol"
    if fix_type in {
        "move_to_map_value",
        "use_correct_map_pointer",
        "use_map_value",
        "use_stack_copy",
        "use_valid_pointer",
    }:
        return "protocol"
    if any(
        token in tags
        for token in [
            "irq_state",
            "critical_section",
        ]
    ):
        return "protocol"
    if (
        taxonomy == "environment_or_configuration"
        or fix_type
        in {
            "env_fix",
            "change_prog_type",
            "build_metadata",
            "loader_fix",
            "helper_switch",
            "use_helper_or_correct_context",
        }
        or "helper_availability" in tags
        or "program_type" in tags
        or "btf" in tags
    ):
        return "environment"
    if taxonomy == "verifier_limit" or fix_type in {"loop_rewrite", "reduce_stack"}:
        return "budget"
    if "verifier_budget" in tags:
        return "budget"
    if fix_type == "null_check" or "nullable" in tags:
        return "null"
    if fix_type == "refcount" or "reference" in tags:
        return "release"
    if fix_type in {
        "initialization",
        "initialize_output_register",
        "initialize_return",
        "initialize_pointer",
    } or "stack_read" in tags:
        return "initialize"
    if any(token in fix_type for token in ["bounds", "clamp", "range", "arithmetic"]):
        return "bounds"
    if any(
        token in fix_type
        for token in [
            "align",
            "wide",
            "compiler",
            "materialization",
            "truncation",
            "merge",
            "signature",
            "inline",
            "reorder",
            "cast",
            "pointer",
            "context",
            "map_value",
            "map_pointer",
            "stack_copy",
            "use_valid_pointer",
            "use_correct_pointer",
            "use_map_value",
            "preserve",
        ]
    ):
        return "provenance"
    return "unspecified"


def bpfix_action(diagnostic: dict) -> str:
    if diagnostic.get("next_action"):
        return diagnostic["next_action"]

    return bpfix_prose_action(diagnostic)


def bpfix_prose_action(diagnostic: dict) -> str:
    text = " ".join(diagnostic.get("help") or [])
    text += " " + diagnostic.get("required_proof", "")
    text += " " + diagnostic.get("message", "")
    lower = text.lower()
    failure_class = diagnostic["failure_class"]
    if failure_class == "environment_or_configuration" or any(
        token in lower
        for token in [
            "kernel version",
            "program type",
            "attach type",
            "btf availability",
            "capabilities",
            "supported helper",
            "kernel capabilities",
        ]
    ):
        return "environment"
    if failure_class == "verifier_limit" or any(
        token in lower
        for token in ["loop bound", "split complex", "state growth", "stack usage", "budget"]
    ):
        return "budget"
    if "null" in lower:
        return "null"
    if "release" in lower:
        return "release"
    if "initialize" in lower or "initialized" in lower:
        return "initialize"
    if any(
        token in lower
        for token in [
            "clamp",
            "bounds",
            "bound the scalar",
            "upper and lower",
            "data_end",
            "access range",
            "map value",
            "packet",
            "scalar range",
            "same ssa value",
        ]
    ):
        return "bounds"
    if any(
        token in lower
        for token in [
            "branch-specific",
            "rederive",
            "pointer provenance",
            "integer casts",
            "turn the pointer into a scalar",
            "verifier-recognized pointer",
        ]
    ):
        return "provenance"
    return "other"


def run_bpfix(
    bpfix_bin: pathlib.Path,
    log_path: pathlib.Path,
    object_path: pathlib.Path | None,
) -> Prediction:
    cmd = [str(bpfix_bin)]
    if object_path is not None:
        cmd.extend(["--object", str(object_path)])
    cmd.append(str(log_path))
    started = time.perf_counter()
    completed = subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    duration_ms = (time.perf_counter() - started) * 1000.0
    diagnostic = parse_bpfix_text(completed.stdout)
    prose_action = bpfix_prose_action(diagnostic)
    pc_candidates: list[int] = []
    source_span = diagnostic.get("source_span") or {}
    if source_span.get("instruction_pc") is not None:
        pc_candidates.append(source_span["instruction_pc"])
    for span in diagnostic.get("related_spans") or []:
        if span.get("instruction_pc") is not None:
            pc_candidates.append(span["instruction_pc"])
    metadata = diagnostic.get("metadata") or {}
    return Prediction(
        error_id=diagnostic["error_id"],
        failure_class=diagnostic["failure_class"],
        action=diagnostic.get("next_action") or prose_action,
        prose_action=prose_action,
        primary_span=bool(diagnostic.get("source_span")),
        related_spans=len(diagnostic.get("related_spans") or []),
        pc_candidates=pc_candidates,
        analysis_error=metadata.get("analysis_error"),
        object_requested=object_path is not None,
        object_programs=0,
        object_site_count=0,
        object_state_site_count=0,
        object_attach_errors=0,
        object_analysis_error=metadata.get("object_analysis_error"),
        duration_ms=duration_ms,
    )


def parse_bpfix_text(text: str) -> dict:
    lines = text.splitlines()
    header = re.match(r"error\[(?P<id>[^\]]+)\]:\s*(?P<message>.*)", lines[0] if lines else "")
    if header is None:
        raise ValueError("bpfix output did not start with an error header")

    diagnostic: dict[str, object] = {
        "error_id": header.group("id"),
        "message": header.group("message"),
        "failure_class": "source_bug",
        "next_action": None,
        "required_proof": "",
        "help": [],
        "source_span": {},
        "related_spans": [],
        "metadata": {},
    }
    metadata: dict[str, object] = {}
    pc_candidates: list[int] = []

    for line in lines[1:]:
        stripped = line.strip()
        if stripped.startswith("= class:"):
            diagnostic["failure_class"] = stripped.removeprefix("= class:").strip()
        elif stripped.startswith("= next action:"):
            diagnostic["next_action"] = stripped.removeprefix("= next action:").strip()
        elif stripped.startswith("= required proof:"):
            diagnostic["required_proof"] = stripped.removeprefix("= required proof:").strip()
        elif stripped.startswith("--> "):
            location = stripped.removeprefix("--> ").rsplit(":", 1)
            if len(location) == 2 and location[1].isdigit():
                diagnostic["source_span"] = {
                    "path": location[0],
                    "line_start": int(location[1]),
                }
        elif stripped.startswith("= note: nearest BPF instruction pc "):
            pc = stripped.removeprefix("= note: nearest BPF instruction pc ")
            if pc.isdigit():
                pc_candidates.append(int(pc))
        elif stripped.startswith("= warning: object analysis:"):
            metadata["object_analysis_error"] = stripped.removeprefix(
                "= warning: object analysis:"
            ).strip()
        elif stripped.startswith("= warning:"):
            metadata["analysis_error"] = stripped.removeprefix("= warning:").strip()
        elif stripped.startswith("help:"):
            diagnostic["help"].append(stripped.removeprefix("help:").strip())
        elif stripped.startswith("| -"):
            diagnostic["related_spans"].append({})

    if pc_candidates:
        diagnostic["source_span"]["instruction_pc"] = pc_candidates[0]
        diagnostic["related_spans"].extend({"instruction_pc": pc} for pc in pc_candidates[1:])
    diagnostic["metadata"] = metadata
    return diagnostic


def load_rows(
    bench_root: pathlib.Path,
    bpfix_bin: pathlib.Path,
    object_if_available: bool = False,
) -> list[Row]:
    manifest = yaml.safe_load((bench_root / "manifest.yaml").read_text())
    source_by_case = {entry["case_id"]: entry["source_kind"] for entry in manifest["cases"]}
    rows: list[Row] = []
    for case_yaml in sorted((bench_root / "cases").glob("*/case.yaml")):
        case_id = case_yaml.parent.name
        data = with_case_defaults(yaml.safe_load(case_yaml.read_text()), manifest)
        label = data["label"]
        capture = data["capture"]
        log_path = case_yaml.parent / capture.get("verifier_log", "replay-verifier.log")
        object_path = None
        if object_if_available:
            candidate = case_yaml.parent / data.get("reproducer", {}).get(
                "object_path", "prog.o"
            )
            if candidate.exists():
                object_path = candidate
        rows.append(
            Row(
                case_id=case_id,
                source_kind=source_by_case[case_id],
                taxonomy=label["taxonomy_class"],
                label_error_id=label.get("error_id", ""),
                label_action=label_action(label),
                root_pc=label.get("root_cause_insn_idx"),
                confidence=label.get("confidence", ""),
                bpfix=run_bpfix(bpfix_bin, log_path, object_path),
                terminal=terminal_dictionary(capture.get("terminal_error") or ""),
            )
        )
    return rows


def ratio(numerator: int, denominator: int) -> str:
    pct = (100.0 * numerator / denominator) if denominator else 0.0
    return f"{numerator}/{denominator} ({pct:.1f}%)"


def latency_summary(predictions: Iterable[Prediction]) -> tuple[float, float, float]:
    values = sorted(prediction.duration_ms for prediction in predictions)
    if not values:
        return (0.0, 0.0, 0.0)
    median = percentile(values, 50)
    p95 = percentile(values, 95)
    return (median, p95, values[-1])


def percentile(values: list[float], pct: int) -> float:
    if len(values) == 1:
        return values[0]
    rank = (pct / 100.0) * (len(values) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(values) - 1)
    weight = rank - lower
    return values[lower] * (1.0 - weight) + values[upper] * weight


def ms(value: float) -> str:
    return f"{value:.1f} ms"


def macro_f1(gold_pred: Iterable[tuple[str, str]]) -> float:
    pairs = list(gold_pred)
    values = []
    for klass in TAXONOMY_CLASSES:
        tp = sum(1 for gold, pred in pairs if gold == klass and pred == klass)
        fp = sum(1 for gold, pred in pairs if gold != klass and pred == klass)
        fn = sum(1 for gold, pred in pairs if gold == klass and pred != klass)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        values.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return sum(values) / len(values)


def exact_root(rows: list[Row], prediction: str, within: int | None = None) -> tuple[int, int]:
    eligible = [row for row in rows if row.root_pc is not None]
    hits = 0
    for row in eligible:
        pred = getattr(row, prediction)
        if within is None:
            hits += any(pc == row.root_pc for pc in pred.pc_candidates)
        else:
            hits += any(abs(pc - row.root_pc) <= within for pc in pred.pc_candidates)
    return hits, len(eligible)


def emit_summary(rows: list[Row]) -> None:
    total = len(rows)
    action_labeled = [row for row in rows if row.label_action != "unspecified"]
    root_exact, root_total = exact_root(rows, "bpfix")
    root_w5, _ = exact_root(rows, "bpfix", within=5)
    term_root, _ = exact_root(rows, "terminal")
    bpfix_median, bpfix_p95, bpfix_max = latency_summary(row.bpfix for row in rows)

    metrics = [
        (
            "known error id",
            ratio(sum(row.bpfix.error_id != "BPFIX-UNKNOWN" for row in rows), total),
            ratio(sum(row.terminal.error_id != "BPFIX-UNKNOWN" for row in rows), total),
        ),
        (
            "error-id exact",
            ratio(sum(row.bpfix.error_id == row.label_error_id for row in rows), total),
            ratio(sum(row.terminal.error_id == row.label_error_id for row in rows), total),
        ),
        (
            "taxonomy agreement",
            ratio(sum(row.bpfix.failure_class == row.taxonomy for row in rows), total),
            ratio(sum(row.terminal.failure_class == row.taxonomy for row in rows), total),
        ),
        (
            "taxonomy macro-F1",
            f"{macro_f1((row.taxonomy, row.bpfix.failure_class) for row in rows):.3f}",
            f"{macro_f1((row.taxonomy, row.terminal.failure_class) for row in rows):.3f}",
        ),
        (
            "lowering-artifact recall",
            ratio(
                sum(
                    row.taxonomy == "lowering_artifact"
                    and row.bpfix.failure_class == "lowering_artifact"
                    for row in rows
                ),
                sum(row.taxonomy == "lowering_artifact" for row in rows),
            ),
            ratio(0, sum(row.taxonomy == "lowering_artifact" for row in rows)),
        ),
        (
            "environment recall",
            ratio(
                sum(
                    row.taxonomy == "environment_or_configuration"
                    and row.bpfix.failure_class == "environment_or_configuration"
                    for row in rows
                ),
                sum(row.taxonomy == "environment_or_configuration" for row in rows),
            ),
            ratio(
                sum(
                    row.taxonomy == "environment_or_configuration"
                    and row.terminal.failure_class == "environment_or_configuration"
                    for row in rows
                ),
                sum(row.taxonomy == "environment_or_configuration" for row in rows),
            ),
        ),
        (
            "verifier-false-positive recall",
            ratio(
                sum(
                    row.taxonomy == "verifier_false_positive"
                    and row.bpfix.failure_class == "verifier_false_positive"
                    for row in rows
                ),
                sum(row.taxonomy == "verifier_false_positive" for row in rows),
            ),
            ratio(0, sum(row.taxonomy == "verifier_false_positive" for row in rows)),
        ),
        (
            "verifier-limit recall",
            ratio(
                sum(
                    row.taxonomy == "verifier_limit"
                    and row.bpfix.failure_class == "verifier_limit"
                    for row in rows
                ),
                sum(row.taxonomy == "verifier_limit" for row in rows),
            ),
            ratio(
                sum(
                    row.taxonomy == "verifier_limit"
                    and row.terminal.failure_class == "verifier_limit"
                    for row in rows
                ),
                sum(row.taxonomy == "verifier_limit" for row in rows),
            ),
        ),
        (
            "primary span emitted",
            ratio(sum(row.bpfix.primary_span for row in rows), total),
            ratio(0, total),
        ),
        (
            "related proof spans emitted",
            ratio(sum(row.bpfix.related_spans > 0 for row in rows), total),
            ratio(0, total),
        ),
        (
            f"root pc exact, labeled subset n={root_total}",
            ratio(root_exact, root_total),
            ratio(term_root, root_total),
        ),
        (
            f"root pc within 5, labeled subset n={root_total}",
            ratio(root_w5, root_total),
            ratio(0, root_total),
        ),
        (
            f"next-action contract exact, labeled subset n={len(action_labeled)}",
            ratio(
                sum(row.bpfix.action == row.label_action for row in action_labeled),
                len(action_labeled),
            ),
            ratio(
                sum(row.terminal.action == row.label_action for row in action_labeled),
                len(action_labeled),
            ),
        ),
        (
            f"legacy prose-action proxy exact, labeled subset n={len(action_labeled)}",
            ratio(
                sum(row.bpfix.prose_action == row.label_action for row in action_labeled),
                len(action_labeled),
            ),
            ratio(
                sum(row.terminal.prose_action == row.label_action for row in action_labeled),
                len(action_labeled),
            ),
        ),
        (
            "bpfix CLI wall time, median/p95/max",
            f"{ms(bpfix_median)} / {ms(bpfix_p95)} / {ms(bpfix_max)}",
            "n/a",
        ),
    ]

    print("| metric | BPFix full log | terminal dictionary |")
    print("| --- | ---: | ---: |")
    for metric, bpfix, terminal in metrics:
        print(f"| {metric} | {bpfix} | {terminal} |")


def fallback_rows(rows: list[Row]) -> list[Row]:
    return [row for row in rows if row.bpfix.error_id in FALLBACK_ERROR_IDS]


def emit_fallback_gate(rows: list[Row]) -> bool:
    failures = fallback_rows(rows)
    print(f"\nfallback/unknown replay gate: {len(failures)}")
    if not failures:
        return True

    print("| case_id | error_id | failure_class |")
    print("| --- | --- | --- |")
    for row in failures:
        print(
            f"| `{row.case_id}` | {row.bpfix.error_id} | "
            f"{row.bpfix.failure_class} |"
        )
    return False


def emit_confusion(rows: list[Row], prediction: str) -> None:
    confusion: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for row in rows:
        confusion[row.taxonomy][getattr(row, prediction).failure_class] += 1
    predicted = sorted({klass for counts in confusion.values() for klass in counts})
    print("| ground truth | " + " | ".join(predicted) + " |")
    print("| --- | " + " | ".join("---:" for _ in predicted) + " |")
    for gold in TAXONOMY_CLASSES:
        counts = confusion.get(gold, {})
        print("| " + gold + " | " + " | ".join(str(counts.get(pred, 0)) for pred in predicted) + " |")


def emit_coverage(rows: list[Row]) -> None:
    print("\nBPFix coverage by expected action:\n")
    print(
        "| expected action | cases | taxonomy agreement | action exact | primary span | related spans | root exact | root within 5 |"
    )
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for action in sorted({row.label_action for row in rows if row.label_action != "unspecified"}):
        bucket = [row for row in rows if row.label_action == action]
        rooted = [row for row in bucket if row.root_pc is not None]
        root_exact = sum(
            any(pc == row.root_pc for pc in row.bpfix.pc_candidates) for row in rooted
        )
        root_within_5 = sum(
            any(abs(pc - row.root_pc) <= 5 for pc in row.bpfix.pc_candidates)
            for row in rooted
        )
        print(
            f"| {action} | {len(bucket)} | "
            f"{ratio(sum(row.bpfix.failure_class == row.taxonomy for row in bucket), len(bucket))} | "
            f"{ratio(sum(row.bpfix.action == row.label_action for row in bucket), len(bucket))} | "
            f"{ratio(sum(row.bpfix.primary_span for row in bucket), len(bucket))} | "
            f"{ratio(sum(row.bpfix.related_spans > 0 for row in bucket), len(bucket))} | "
            f"{ratio(root_exact, len(rooted))} | "
            f"{ratio(root_within_5, len(rooted))} |"
        )

    skipped = sum(row.label_action == "unspecified" for row in rows)
    if skipped:
        print(
            f"\nAction labels marked unspecified and skipped for action exact: {skipped}/{len(rows)}"
        )

    if any(row.bpfix.object_requested for row in rows):
        emit_object_coverage(rows)


def emit_object_coverage(rows: list[Row]) -> None:
    object_rows = [row for row in rows if row.bpfix.object_requested]
    print("\nBPFix object-analysis coverage:\n")
    print("| metric | value |")
    print("| --- | ---: |")
    print(f"| cases run with --object | {len(object_rows)} |")
    print(
        f"| cases with parsed object programs | "
        f"{ratio(sum(row.bpfix.object_programs > 0 for row in object_rows), len(object_rows))} |"
    )
    print(
        f"| cases with attached verifier states | "
        f"{ratio(sum(row.bpfix.object_state_site_count > 0 for row in object_rows), len(object_rows))} |"
    )
    print(
        f"| cases with object-analysis error | "
        f"{ratio(sum(row.bpfix.object_analysis_error is not None for row in object_rows), len(object_rows))} |"
    )
    print(
        f"| object programs parsed | "
        f"{sum(row.bpfix.object_programs for row in object_rows)} |"
    )
    print(
        f"| object CFG sites | "
        f"{sum(row.bpfix.object_site_count for row in object_rows)} |"
    )
    print(
        f"| verifier states attached to object sites | "
        f"{sum(row.bpfix.object_state_site_count for row in object_rows)} |"
    )
    print(
        f"| per-program attach errors | "
        f"{sum(row.bpfix.object_attach_errors for row in object_rows)} |"
    )

    failures = [
        row
        for row in object_rows
        if row.bpfix.object_analysis_error is not None or row.bpfix.object_attach_errors > 0
    ]
    if failures:
        if len(failures) > 20:
            print(f"\nFirst 20 object-analysis issues out of {len(failures)}:")
        print("\n| case_id | object_analysis_error | attach_errors |")
        print("| --- | --- | ---: |")
        for row in failures[:20]:
            error = row.bpfix.object_analysis_error or "none"
            print(f"| `{row.case_id}` | {error} | {row.bpfix.object_attach_errors} |")


def stable_key(seed: str, *parts: str) -> str:
    data = "\0".join([seed, *parts]).encode()
    return hashlib.sha256(data).hexdigest()


def stratified_sample(rows: list[Row], size: int, seed: str) -> list[Row]:
    """Return a deterministic high-signal sample.

    The sample includes all non-source-bug cases first, then fills from
    source_bug cases while balancing source strata.  This prevents the dominant
    source_bug class from hiding the hard taxonomy edges.
    """

    minority = [row for row in rows if row.taxonomy != "source_bug"]
    minority.sort(key=lambda row: stable_key(seed, row.taxonomy, row.source_kind, row.case_id))
    if len(minority) >= size:
        return minority[:size]

    selected = list(minority)
    remaining = size - len(selected)
    by_source: dict[str, list[Row]] = collections.defaultdict(list)
    for row in rows:
        if row.taxonomy == "source_bug":
            by_source[row.source_kind].append(row)
    for bucket in by_source.values():
        bucket.sort(key=lambda row: stable_key(seed, row.source_kind, row.case_id))

    sources = sorted(by_source)
    while remaining > 0 and sources:
        progressed = False
        for source in sources:
            bucket = by_source[source]
            if not bucket:
                continue
            selected.append(bucket.pop(0))
            remaining -= 1
            progressed = True
            if remaining == 0:
                break
        if not progressed:
            break
    return selected


def proof_score(row: Row, prediction: Prediction) -> str:
    if prediction.error_id == row.label_error_id:
        return "exact"
    if prediction.error_id == "BPFIX-UNKNOWN":
        return "miss"
    action_matches = (
        row.label_action != "unspecified" and prediction.action == row.label_action
    )
    if prediction.failure_class == row.taxonomy or action_matches:
        return "partial"
    return "miss"


def root_score(row: Row, prediction: Prediction) -> str:
    if row.root_pc is None or not prediction.pc_candidates:
        return "na" if row.root_pc is None else "miss"
    if any(pc == row.root_pc for pc in prediction.pc_candidates):
        return "exact"
    if any(abs(pc - row.root_pc) <= 5 for pc in prediction.pc_candidates):
        return "near"
    return "miss"


def action_score(row: Row, prediction: Prediction) -> str:
    if row.label_action == "unspecified":
        return "na"
    if prediction.action == row.label_action:
        return "correct"
    source_like = {
        "bounds",
        "provenance",
        "null",
        "initialize",
        "release",
        "protocol",
        "context",
        "other",
    }
    if row.label_action in {"environment", "budget"} and prediction.action in source_like:
        return "unsafe"
    if row.label_action in source_like and prediction.action in {"environment", "budget"}:
        return "unsafe"
    if row.label_action == "other" or prediction.action == "other":
        return "partial"
    return "partial"


def count_scores(rows: list[Row], prediction: str, scorer) -> collections.Counter[str]:
    return collections.Counter(scorer(row, getattr(row, prediction)) for row in rows)


def emit_sample_audit(rows: list[Row], size: int, seed: str) -> None:
    sample = stratified_sample(rows, size, seed)
    taxonomy = collections.Counter(row.taxonomy for row in sample)
    source = collections.Counter(row.source_kind for row in sample)

    print(f"sample_size: {len(sample)}")
    print("taxonomy:", dict(sorted(taxonomy.items())))
    print("source_kind:", dict(sorted(source.items())))
    print()

    print("| metric | BPFix full log | terminal dictionary |")
    print("| --- | ---: | ---: |")
    for metric, scorer in [
        ("required proof", proof_score),
        ("root pc", root_score),
        ("next action", action_score),
    ]:
        bpfix = count_scores(sample, "bpfix", scorer)
        terminal = count_scores(sample, "terminal", scorer)
        labels = sorted(set(bpfix) | set(terminal))
        print(
            f"| {metric} | "
            + ", ".join(f"{label} {bpfix[label]}" for label in labels)
            + " | "
            + ", ".join(f"{label} {terminal[label]}" for label in labels)
            + " |"
        )

    print()
    print("| case_id | source | taxonomy | label_action |")
    print("| --- | --- | --- | --- |")
    for row in sample:
        print(f"| `{row.case_id}` | {row.source_kind} | {row.taxonomy} | {row.label_action} |")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bench-root", default="bpfix-bench", type=pathlib.Path)
    parser.add_argument("--bpfix-bin", default="target/debug/bpfix", type=pathlib.Path)
    parser.add_argument("--confusion", action="store_true")
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--sample-audit", action="store_true")
    parser.add_argument("--sample-size", default=80, type=int)
    parser.add_argument("--sample-seed", default="bpfix-eval-v1")
    parser.add_argument(
        "--object-if-available",
        action="store_true",
        help="Pass each case's object_path to bpfix when the object exists.",
    )
    parser.add_argument(
        "--reject-fallback",
        action="store_true",
        help="Exit non-zero if any replay case emits UNKNOWN, input_error, or unsupported diagnostics.",
    )
    args = parser.parse_args()

    if not args.bpfix_bin.exists():
        print(f"missing bpfix binary: {args.bpfix_bin}", file=sys.stderr)
        return 2

    rows = load_rows(args.bench_root, args.bpfix_bin, args.object_if_available)
    emit_summary(rows)
    if args.confusion:
        print("\nBPFix confusion:\n")
        emit_confusion(rows, "bpfix")
        print("\nTerminal dictionary confusion:\n")
        emit_confusion(rows, "terminal")
    if args.coverage:
        emit_coverage(rows)
    if args.sample_audit:
        print("\nStratified sample audit:\n")
        emit_sample_audit(rows, args.sample_size, args.sample_seed)
    if args.reject_fallback and not emit_fallback_gate(rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
