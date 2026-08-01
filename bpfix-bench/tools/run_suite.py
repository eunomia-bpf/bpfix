#!/usr/bin/env python3
"""Run or smoke-test the bpfix-bench LLM repair suite."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SKILL_SCRIPT_DIR = (
    Path(__file__).resolve().parents[2] / "skills" / "ebpf-verifier-repair" / "scripts"
)
sys.path.insert(0, str(SKILL_SCRIPT_DIR))
from extract_verifier_failure import compact_verifier_log  # noqa: E402


DEFAULT_BASE_URL = "http://127.0.0.1:18080/v1"
DEFAULT_MODEL = "Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M"
MODES = ["source-only", "raw", "trimmed-raw", "bpfix", "skills"]
TOKEN_USAGE_FIELDS = [
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "reasoning_tokens",
    "cached_prompt_tokens",
]
SKILL_REPAIR_DIR = Path("skills") / "ebpf-verifier-repair"
SKILL_FILES = [
    SKILL_REPAIR_DIR / "SKILL.md",
    SKILL_REPAIR_DIR / "references" / "raw-log-triage.md",
    SKILL_REPAIR_DIR / "references" / "semantic-preservation.md",
    SKILL_REPAIR_DIR / "references" / "failure-directed-retry.md",
    SKILL_REPAIR_DIR / "references" / "repair-patterns.md",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def discover_cases(root: Path) -> list[Path]:
    cases_root = root / "bpfix-bench" / "cases"
    return sorted(case for case in cases_root.iterdir() if (case / "buggy.bpf.c").exists())


def read_split_file(path: Path) -> list[str]:
    cases: list[str] = []
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if "/" in line or line.endswith(".txt"):
            raise SystemExit(f"{path}:{line_no}: split entries must be case ids, got {line!r}")
        cases.append(line)
    return cases


def run(argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)


def command_text(argv: list[str], *, cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    return (completed.stdout + completed.stderr).strip()


def first_line(text: str) -> str | None:
    lines = text.splitlines()
    return lines[0] if lines else None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def markdown_section(text: str, heading: str) -> str:
    match = re.search(rf"^{re.escape(heading)}\n(?P<body>.*?)(?=^## |\Z)", text, flags=re.DOTALL | re.MULTILINE)
    if not match:
        raise ValueError(f"missing markdown section: {heading}")
    return match.group("body").strip()


def markdown_from_heading(text: str, heading: str) -> str:
    match = re.search(rf"^{re.escape(heading)}\n(?P<body>.*)", text, flags=re.DOTALL | re.MULTILINE)
    if not match:
        raise ValueError(f"missing markdown heading: {heading}")
    return f"{heading}\n{match.group('body').strip()}"


def skill_file_metadata(root: Path) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    for relative in SKILL_FILES:
        path = root / relative
        files.append(
            {
                "path": str(relative),
                "sha256": sha256_file(path) if path.exists() else None,
                "exists": path.exists(),
            }
        )
    return files


def skills_prompt_guidance(root: Path) -> str:
    skill = (root / SKILL_FILES[0]).read_text(encoding="utf-8")
    raw_log_triage = (root / SKILL_FILES[1]).read_text(encoding="utf-8")
    semantic_preservation = (root / SKILL_FILES[2]).read_text(encoding="utf-8")
    failure_directed_retry = (root / SKILL_FILES[3]).read_text(encoding="utf-8")
    patterns = (root / SKILL_FILES[4]).read_text(encoding="utf-8")
    source_rules = markdown_section(skill, "## Source Editing Rules")
    repair_patterns = markdown_from_heading(patterns, "## Bounds")
    return f"""Repair verifier failures as missing proof obligations, not as string-matched terminal errors.
Make the smallest verifier-visible source change that preserves program semantics.
Do not use a BPFix diagnostic in this prompt mode; use only the source, raw verifier log, and these rules.

Source Editing Rules
{source_rules}

Raw Log Triage
{raw_log_triage}

Semantic Preservation
{semantic_preservation}

Failure-Directed Retry
{failure_directed_retry}

Repair Patterns
{repair_patterns}
"""


def trim_verifier_log(log: str) -> str:
    begin = log.find("BEGIN PROG LOAD LOG")
    end = log.find("-- END PROG LOAD LOG --")
    if begin == -1 or end == -1:
        return log.strip() + "\n"

    line_start = log.rfind("\n", 0, begin)
    line_start = 0 if line_start == -1 else line_start + 1
    line_end = log.find("\n", end)
    line_end = len(log) if line_end == -1 else line_end
    return log[line_start:line_end].strip() + "\n"


def git_metadata(root: Path) -> dict[str, object]:
    commit = command_text(["git", "rev-parse", "HEAD"], cwd=root)
    status = command_text(["git", "status", "--short"], cwd=root)
    return {
        "commit": commit or None,
        "dirty": bool(status.strip()),
    }


def model_file_metadata(path: Path | None, supplied_sha256: str | None) -> dict[str, object]:
    if path is None:
        return {"path": None, "exists": False, "size_bytes": None, "sha256": supplied_sha256}
    resolved = path.expanduser().resolve()
    exists = resolved.exists()
    size = resolved.stat().st_size if exists else None
    return {
        "path": str(resolved),
        "exists": exists,
        "size_bytes": size,
        "sha256": supplied_sha256,
    }


def llama_cpp_metadata(path: Path | None) -> dict[str, object]:
    if path is None:
        return {"path": None, "commit": None}
    resolved = path.expanduser().resolve()
    commit = command_text(["git", "rev-parse", "HEAD"], cwd=resolved) if resolved.exists() else ""
    return {"path": str(resolved), "commit": commit or None}


def server_model_metadata(base_url: str) -> dict[str, object]:
    request = urllib.request.Request(base_url.rstrip("/") + "/models", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=2.0) as response:
            return {"reachable": True, "models": json.loads(response.read().decode("utf-8"))}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return {"reachable": False, "models": None}


def split_metadata(args: argparse.Namespace) -> dict[str, object]:
    if args.split is None:
        return {
            "path": None,
            "sha256": None,
            "case_count": None,
            "expected_count": args.expected_count,
            "allow_empty": args.allow_empty_split,
        }
    resolved = args.split.resolve()
    cases = read_split_file(args.split)
    return {
        "path": str(resolved),
        "sha256": sha256_file(resolved),
        "case_count": len(cases),
        "expected_count": args.expected_count,
        "allow_empty": args.allow_empty_split,
    }


def run_metadata(args: argparse.Namespace, root: Path) -> dict[str, object]:
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "runner": {
            "argv": sys.argv,
        },
        "git": git_metadata(root),
        "toolchain": {
            "kernel": command_text(["uname", "-a"]),
            "clang": first_line(command_text(["clang", "--version"])),
            "bpftool": command_text(["bpftool", "version"]).splitlines(),
            "llvm_objdump": first_line(command_text(["llvm-objdump", "--version"])),
        },
        "llm": {
            "base_url": args.base_url,
            "model": args.model,
            "temperature": args.temperature,
            "max_tokens": args.max_tokens,
            "timeout_sec": args.timeout,
            "api_key_env": args.api_key_env,
            "extra_body": args.extra_body,
            "model_file": model_file_metadata(args.model_path, args.model_sha256),
            "llama_cpp": llama_cpp_metadata(args.llama_cpp_dir),
            "server": server_model_metadata(args.base_url),
        },
        "case_selection": {
            "split": split_metadata(args),
            "case_overrides": args.case or [],
        },
        "prompt_mode": {
            "mode": args.mode,
            "skill_files": skill_file_metadata(root) if args.mode == "skills" else [],
        },
        "repair_policy": {
            "max_attempts": args.repair_attempts if args.candidate is None and not args.prompt_only else None,
        },
    }


def diagnostic_input(case_dir: Path, mode: str) -> tuple[str | None, str, str]:
    if mode == "source-only":
        return None, "", ""
    if mode == "raw":
        return "raw verifier log", (case_dir / "verifier.log").read_text(encoding="utf-8"), ""
    if mode == "trimmed-raw":
        raw_log = (case_dir / "verifier.log").read_text(encoding="utf-8")
        return "trimmed raw verifier log", trim_verifier_log(raw_log), ""
    if mode == "bpfix":
        return (
            "BPFix plain-text diagnostic",
            (case_dir / "diagnostic.txt").read_text(encoding="utf-8"),
            "",
        )
    if mode == "skills":
        raw_log = (case_dir / "verifier.log").read_text(encoding="utf-8")
        return (
            "raw verifier failure slice",
            compact_verifier_log(raw_log),
            (
                "Use the eBPF verifier repair skill guidance below. "
                "Do not use or infer from a BPFix plain-text diagnostic."
            ),
        )
    raise ValueError(f"unknown mode: {mode}")


def build_prompt(case_dir: Path, mode: str) -> str:
    source = (case_dir / "buggy.bpf.c").read_text(encoding="utf-8")
    diagnostic_label, diagnostic, diagnostic_guidance = diagnostic_input(case_dir, mode)
    diagnostic_block = ""
    if diagnostic_label is None:
        diagnostic_block = "\nNo verifier diagnostic is provided for this baseline.\n"
    else:
        diagnostic_block = f"""
{diagnostic_label}:
```text
{diagnostic}
```
"""
    skill_block = ""
    if mode == "skills":
        skill_block = f"""
Repair skill guidance:
```text
{skills_prompt_guidance(repo_root())}
```
"""

    return f"""You are fixing one eBPF verifier rejection.

Return only one complete replacement C source file in a fenced ```c block.
Do not explain. Do not output a diff. Preserve the intended packet/helper
semantics; do not remove the program, maps, SEC() section, or license.
{diagnostic_guidance}
{skill_block}

Source file:
```c
{source}
```
{diagnostic_block}
"""


def truncate_middle(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    return text[:head] + "\n... <truncated> ...\n" + text[-tail:]


def oracle_retry_context(completed: subprocess.CompletedProcess[str], candidate_source: str) -> str:
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        report = {}
    failure_stage = oracle_failure_stage(completed)
    chunks = [
        "Previous repair attempt failed.",
        f"Failure stage: {failure_stage}",
        "",
        "Previous candidate source:",
        "```c",
        truncate_middle(candidate_source, 20000),
        "```",
    ]
    if isinstance(report, dict):
        compile_report = report.get("compile")
        if isinstance(compile_report, dict) and compile_report.get("returncode") != 0:
            chunks.extend(
                [
                    "",
                    "Compiler stderr from previous attempt:",
                    "```text",
                    truncate_middle(str(compile_report.get("stderr", "")), 12000),
                    "```",
                ]
            )
        load_report = report.get("load")
        if isinstance(load_report, dict) and load_report.get("returncode") != 0:
            chunks.extend(
                [
                    "",
                    "Verifier/load output from previous attempt:",
                    "```text",
                    truncate_middle(str(load_report.get("stderr", "")) + str(load_report.get("stdout", "")), 20000),
                    "```",
                ]
            )
        failed_checks = []
        for check in report.get("success_log_checks", []):
            if isinstance(check, dict) and check.get("passed") is not True:
                failed_checks.append(check)
        for functional in report.get("functional", []):
            if isinstance(functional, dict) and functional.get("passed") is not True:
                failed_checks.append(functional)
        if failed_checks:
            chunks.extend(
                [
                    "",
                    "Failed oracle checks from previous attempt:",
                    "```json",
                    truncate_middle(json.dumps(failed_checks, indent=2, sort_keys=True), 16000),
                    "```",
                ]
            )
    elif completed.stdout or completed.stderr:
        chunks.extend(
            [
                "",
                "Oracle output from previous attempt:",
                "```text",
                truncate_middle(completed.stdout + completed.stderr, 16000),
                "```",
            ]
        )
    chunks.extend(
        [
            "",
            "Try again. Return only one complete replacement C source file in a fenced ```c block.",
        ]
    )
    return "\n".join(chunks)


def extract_retry_context(response: str, error: ValueError) -> str:
    return "\n".join(
        [
            "Previous repair attempt did not return a complete replacement C source file.",
            f"Extraction error: {error}",
            "",
            "Previous model response:",
            "```text",
            truncate_middle(response, 20000),
            "```",
            "",
            "Try again. Return only one complete replacement C source file in a fenced ```c block.",
            "Do not nest code fences inside the C code block.",
        ]
    )


def append_retry_context(prompt: str, retry_context: str | None) -> str:
    if retry_context is None:
        return prompt
    return f"{prompt}\n\nRetry context:\n{retry_context}\n"


def nested_int(value: object, *path: str) -> int | None:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    if isinstance(current, bool) or not isinstance(current, int) or current < 0:
        return None
    return current


def first_reported_int(value: object, *paths: tuple[str, ...]) -> int | None:
    for path in paths:
        result = nested_int(value, *path)
        if result is not None:
            return result
    return None


def normalize_token_usage(raw_usage: object) -> dict[str, int | None] | None:
    if not isinstance(raw_usage, dict):
        return None
    normalized = {
        "prompt_tokens": first_reported_int(raw_usage, ("prompt_tokens",), ("input_tokens",)),
        "completion_tokens": first_reported_int(
            raw_usage,
            ("completion_tokens",),
            ("output_tokens",),
        ),
        "total_tokens": nested_int(raw_usage, "total_tokens"),
        "reasoning_tokens": first_reported_int(
            raw_usage,
            ("completion_tokens_details", "reasoning_tokens"),
            ("output_tokens_details", "reasoning_tokens"),
            ("reasoning_tokens",),
        ),
        "cached_prompt_tokens": first_reported_int(
            raw_usage,
            ("prompt_tokens_details", "cached_tokens"),
            ("input_tokens_details", "cached_tokens"),
        ),
    }
    return normalized if any(value is not None for value in normalized.values()) else None


def aggregate_attempt_cost(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    model_calls = [attempt for attempt in attempts if "model_wall_time_seconds" in attempt]
    coverage: dict[str, int] = {}
    totals: dict[str, int | None] = {}
    for field in TOKEN_USAGE_FIELDS:
        reported = [
            usage[field]
            for attempt in model_calls
            if isinstance((usage := attempt.get("token_usage")), dict)
            and isinstance(usage.get(field), int)
        ]
        coverage[field] = len(reported)
        totals[field] = sum(reported) if len(reported) == len(model_calls) else None

    def sum_seconds(field: str) -> float:
        return round(
            sum(
                float(attempt[field])
                for attempt in attempts
                if isinstance(attempt.get(field), (int, float))
            ),
            6,
        )

    return {
        "model_calls": len(model_calls),
        "token_usage_coverage": coverage,
        **totals,
        "model_wall_time_seconds": sum_seconds("model_wall_time_seconds"),
        "oracle_wall_time_seconds": sum_seconds("oracle_wall_time_seconds"),
        "attempt_wall_time_seconds": sum_seconds("attempt_wall_time_seconds"),
    }


def repair_policy_checkpoints(
    results: list[dict[str, Any]],
    max_attempts: int | None = None,
) -> list[dict[str, Any]]:
    observed_attempts = max(
        (
            len(attempts)
            for result in results
            if isinstance((attempts := result.get("attempts")), list)
        ),
        default=0,
    )
    checkpoint_count = observed_attempts if max_attempts is None else max_attempts
    checkpoints: list[dict[str, Any]] = []
    for attempt_limit in range(1, checkpoint_count + 1):
        selected_attempts: list[dict[str, Any]] = []
        passed = 0
        for result in results:
            attempts = result.get("attempts")
            if not isinstance(attempts, list):
                continue
            policy_attempts = attempts[:attempt_limit]
            selected_attempts.extend(policy_attempts)
            if any(attempt.get("status") == "pass" for attempt in policy_attempts):
                passed += 1
        checkpoints.append(
            {
                "max_attempts": attempt_limit,
                "total": len(results),
                "passed": passed,
                "cost": aggregate_attempt_cost(selected_attempts),
            }
        )
    return checkpoints


def call_openai_compatible(
    *,
    base_url: str,
    api_key: str,
    model: str,
    prompt: str,
    timeout: float,
    max_tokens: int,
    temperature: float,
    extra_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You repair eBPF C verifier failures by returning a full corrected source file.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if extra_body:
        body.update(extra_body)
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    raw_usage = payload.get("usage") if isinstance(payload, dict) else None
    raw_timings = payload.get("timings") if isinstance(payload, dict) else None
    choices = payload.get("choices") if isinstance(payload, dict) else None
    choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else None
    message = choice.get("message") if isinstance(choice, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    reasoning_content = message.get("reasoning_content") if isinstance(message, dict) else None
    error = None
    if choice is None:
        error = "response choices[0] is missing or invalid"
    elif not isinstance(message, dict):
        error = "choices[0].message is missing or invalid"
    elif not isinstance(content, str):
        error = "choices[0].message.content is not a string"
    return {
        "content": content if isinstance(content, str) else None,
        "error": error,
        "finish_reason": choice.get("finish_reason") if isinstance(choice, dict) else None,
        "reasoning_chars": len(reasoning_content) if isinstance(reasoning_content, str) else None,
        "token_usage": normalize_token_usage(raw_usage),
        "api_usage": raw_usage if isinstance(raw_usage, dict) else None,
        "api_timings": raw_timings if isinstance(raw_timings, dict) else None,
    }


def extract_source(response: str) -> str:
    match = re.search(r"```(?:c|C)?\s*(.*?)```", response, flags=re.DOTALL)
    if match:
        return match.group(1).strip() + "\n"
    stripped = response.strip()
    if "#include" in stripped and "SEC(" in stripped:
        return stripped + "\n"
    raise ValueError("model response did not contain a complete C source block")


def run_oracle(case_dir: Path, source: Path, work_dir: Path) -> subprocess.CompletedProcess[str]:
    return run(
        [
            sys.executable,
            str(case_dir / "test.py"),
            "--source",
            str(source),
            "--work-dir",
            str(work_dir),
        ],
        cwd=repo_root(),
    )


def oracle_failure_stage(completed: subprocess.CompletedProcess[str]) -> str:
    if completed.returncode == 0:
        return "pass"
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return "oracle_parse"
    if not isinstance(report, dict):
        return "oracle_parse"

    compile_report = report.get("compile")
    if isinstance(compile_report, dict) and compile_report.get("returncode") != 0:
        return "compile"

    for setup in report.get("map_setup", []):
        if isinstance(setup, dict) and setup.get("returncode") != 0:
            return "map_setup"

    load_report = report.get("load")
    if isinstance(load_report, dict) and load_report.get("returncode") != 0:
        return "verifier_load"

    for check in report.get("success_log_checks", []):
        if isinstance(check, dict) and check.get("passed") is not True:
            return "auxiliary_proof_predicate"

    for check in report.get("source_semantics", []):
        if isinstance(check, dict) and check.get("passed") is not True:
            return "auxiliary_proof_predicate"

    for functional in report.get("functional", []):
        if isinstance(functional, dict):
            for update in functional.get("map_updates", []):
                if isinstance(update, dict) and update.get("returncode") != 0:
                    return "map_setup"
            if functional.get("passed") is not True:
                return "functional_oracle"

    return "oracle"


def smoke_case(case_dir: Path, *, fixed: bool = False) -> dict[str, object]:
    missing = [
        name
        for name in ["buggy.bpf.c", "verifier.log", "diagnostic.txt", "test.py"]
        if not (case_dir / name).exists()
    ]
    source_name = "fixed.bpf.c" if fixed else "buggy.bpf.c"
    if fixed and not (case_dir / source_name).exists():
        missing.append(source_name)
    report: dict[str, object] = {"case": case_dir.name, "missing": missing, "passed": False}
    if missing:
        return report
    try:
        diagnostic = (case_dir / "diagnostic.txt").read_text(encoding="utf-8")
        if "error[BPFIX-" not in diagnostic:
            report["diagnostic_error"] = "diagnostic.txt does not look like a BPFix diagnostic"
            return report
    except OSError as exc:
        report["diagnostic_error"] = str(exc)
        return report

    completed = run(
        [
            sys.executable,
            str(case_dir / "test.py"),
            "--source",
            str(case_dir / source_name),
            *(["--expect-reject"] if not fixed else []),
        ],
        cwd=repo_root(),
    )
    report["oracle_stdout"] = completed.stdout
    report["oracle_stderr"] = completed.stderr
    report["oracle_returncode"] = completed.returncode
    report["passed"] = completed.returncode == 0
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    default_model_path = os.environ.get("LLM_MODEL_PATH")
    default_llama_cpp_dir = os.environ.get("LLAMA_CPP_DIR")
    parser.add_argument("--mode", choices=MODES, default="raw")
    parser.add_argument("--smoke", action="store_true", help="Validate fixtures and buggy rejection only.")
    parser.add_argument(
        "--fixed-smoke",
        action="store_true",
        help="Validate fixed.bpf.c repairs with each case's success oracle.",
    )
    parser.add_argument("--prompt-only", action="store_true", help="Write prompts without calling a model.")
    parser.add_argument(
        "--repair-attempts",
        type=int,
        default=1,
        help="Maximum model repair attempts per case. Attempts after the first append prior failure context.",
    )
    parser.add_argument("--split", type=Path, help="Run case ids listed in a split file.")
    parser.add_argument(
        "--allow-empty-split",
        action="store_true",
        help="Allow an explicitly empty --split to select zero cases instead of failing.",
    )
    parser.add_argument("--expected-count", type=int, help="Require the selected split to contain this many cases.")
    parser.add_argument("--case", action="append", help="Run only this case id.")
    parser.add_argument("--candidate", type=Path, help="Evaluate a local candidate source; requires one --case.")
    parser.add_argument("--results-dir", type=Path, default=repo_root() / "bpfix-bench" / "results")
    parser.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", DEFAULT_MODEL))
    parser.add_argument("--api-key-env", default="LLAMA_API_KEY")
    parser.add_argument("--model-path", type=Path, default=Path(default_model_path) if default_model_path else None)
    parser.add_argument("--model-sha256", default=os.environ.get("LLM_MODEL_SHA256"))
    parser.add_argument(
        "--llama-cpp-dir",
        type=Path,
        default=Path(default_llama_cpp_dir) if default_llama_cpp_dir else None,
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument(
        "--extra-body-json",
        default=os.environ.get("LLM_EXTRA_BODY_JSON"),
        help="JSON object merged into each OpenAI-compatible chat/completions request body.",
    )
    return parser.parse_args(argv)


def parse_extra_body_json(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--extra-body-json is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("--extra-body-json must decode to a JSON object")
    return parsed


def select_cases(root: Path, wanted: list[str] | None) -> list[Path]:
    cases = discover_cases(root)
    if not wanted:
        return cases
    seen: set[str] = set()
    duplicates: list[str] = []
    for case_id in wanted:
        if case_id in seen and case_id not in duplicates:
            duplicates.append(case_id)
        seen.add(case_id)
    if duplicates:
        raise SystemExit(f"duplicate case(s): {', '.join(sorted(duplicates))}")

    by_id = {case.name: case for case in cases}
    missing = set(wanted) - set(by_id)
    if missing:
        raise SystemExit(f"unknown case(s): {', '.join(sorted(missing))}")
    return [by_id[case_id] for case_id in wanted]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.extra_body = parse_extra_body_json(args.extra_body_json)
    root = repo_root()
    if args.repair_attempts < 1:
        raise SystemExit("--repair-attempts must be >= 1")
    if args.split is not None and args.case:
        raise SystemExit("--split and --case cannot be combined; use --case without --split for single-case debug runs")

    wanted_cases: list[str] = []
    if args.split is not None:
        split_cases = read_split_file(args.split)
        if not split_cases and not args.allow_empty_split:
            raise SystemExit(f"{args.split}: split is empty; pass --allow-empty-split to run zero cases")
        if args.expected_count is not None and len(split_cases) != args.expected_count:
            raise SystemExit(f"{args.split}: expected {args.expected_count} cases, found {len(split_cases)}")
        wanted_cases.extend(split_cases)
    if args.case:
        wanted_cases.extend(args.case)
    if args.split is not None and not wanted_cases and args.allow_empty_split:
        cases = []
    else:
        cases = select_cases(root, wanted_cases or None)

    if args.smoke and args.fixed_smoke:
        raise SystemExit("--smoke and --fixed-smoke cannot be combined")

    if args.smoke or args.fixed_smoke:
        reports = [smoke_case(case, fixed=args.fixed_smoke) for case in cases]
        key = "fixed_smoke" if args.fixed_smoke else "smoke"
        print(json.dumps({key: reports}, indent=2, sort_keys=True))
        return 0 if all(report["passed"] for report in reports) else 1

    if args.candidate is not None and len(cases) != 1:
        raise SystemExit("--candidate requires exactly one --case")

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    stamp = f"{stamp}-pid{os.getpid()}"
    run_dir = args.results_dir / stamp / args.mode
    run_dir.mkdir(parents=True, exist_ok=True)
    metadata = run_metadata(args, root)
    (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    api_key = os.environ.get(args.api_key_env, "none")
    summary: list[dict[str, Any]] = []
    for case_dir in cases:
        case_out = run_dir / case_dir.name
        case_out.mkdir(parents=True, exist_ok=True)
        prompt_build_started = time.perf_counter()
        base_prompt = build_prompt(case_dir, args.mode)
        (case_out / "prompt.txt").write_text(base_prompt, encoding="utf-8")
        prompt_info = {
            "prompt_sha256": sha256_text(base_prompt),
            "prompt_chars": len(base_prompt),
            "source_chars": len((case_dir / "buggy.bpf.c").read_text(encoding="utf-8")),
            "diagnostic_chars": len(diagnostic_input(case_dir, args.mode)[1]),
            "prompt_build_wall_time_seconds": round(time.perf_counter() - prompt_build_started, 6),
        }

        if args.prompt_only:
            summary.append({"case": case_dir.name, "status": "prompt_written", **prompt_info})
            continue

        if args.candidate is None:
            retry_context = None
            attempts: list[dict[str, Any]] = []
            for attempt in range(1, args.repair_attempts + 1):
                attempt_out = case_out / f"attempt-{attempt}"
                attempt_out.mkdir(parents=True, exist_ok=True)
                attempt_started = time.perf_counter()
                prompt = append_retry_context(base_prompt, retry_context)
                (attempt_out / "prompt.txt").write_text(prompt, encoding="utf-8")
                model_started = time.perf_counter()
                try:
                    model_result = call_openai_compatible(
                        base_url=args.base_url,
                        api_key=api_key,
                        model=args.model,
                        prompt=prompt,
                        timeout=args.timeout,
                        max_tokens=args.max_tokens,
                        temperature=args.temperature,
                        extra_body=args.extra_body,
                    )
                    model_wall_time = round(time.perf_counter() - model_started, 6)
                except (
                    json.JSONDecodeError,
                    urllib.error.URLError,
                    TimeoutError,
                    ConnectionError,
                    http.client.HTTPException,
                ) as exc:
                    model_wall_time = round(time.perf_counter() - model_started, 6)
                    attempt_result = {
                        "attempt": attempt,
                        "status": "model_error",
                        "failure_stage": "model_call",
                        "error": str(exc),
                        "prompt_sha256": sha256_text(prompt),
                        "prompt_chars": len(prompt),
                        "response_chars": None,
                        "reasoning_chars": None,
                        "finish_reason": None,
                        "token_usage": None,
                        "api_usage": None,
                        "api_timings": None,
                        "model_wall_time_seconds": model_wall_time,
                        "oracle_wall_time_seconds": None,
                        "attempt_wall_time_seconds": round(time.perf_counter() - attempt_started, 6),
                    }
                    (attempt_out / "result.json").write_text(
                        json.dumps(attempt_result, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    attempts.append(attempt_result)
                    if attempt == args.repair_attempts:
                        break
                    continue
                response = model_result.get("content")
                model_metrics = {
                    "response_chars": len(response) if isinstance(response, str) else None,
                    "reasoning_chars": model_result.get("reasoning_chars"),
                    "finish_reason": model_result.get("finish_reason"),
                    "token_usage": model_result.get("token_usage"),
                    "api_usage": model_result.get("api_usage"),
                    "api_timings": model_result.get("api_timings"),
                    "model_wall_time_seconds": model_wall_time,
                }
                response_error = model_result.get("error")
                if response_error is not None or not isinstance(response, str):
                    attempt_result = {
                        "attempt": attempt,
                        "status": "model_error",
                        "failure_stage": "model_call",
                        "error": str(response_error or "model response content is unavailable"),
                        "prompt_sha256": sha256_text(prompt),
                        "prompt_chars": len(prompt),
                        **model_metrics,
                        "oracle_wall_time_seconds": None,
                        "attempt_wall_time_seconds": round(time.perf_counter() - attempt_started, 6),
                    }
                    (attempt_out / "result.json").write_text(
                        json.dumps(attempt_result, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    attempts.append(attempt_result)
                    if attempt == args.repair_attempts:
                        break
                    continue
                (attempt_out / "response.txt").write_text(response, encoding="utf-8")
                try:
                    candidate_source = extract_source(response)
                    candidate_path = attempt_out / "candidate.bpf.c"
                    candidate_path.write_text(candidate_source, encoding="utf-8")
                except ValueError as exc:
                    next_retry_context = (
                        extract_retry_context(response, exc)
                        if attempt < args.repair_attempts
                        else None
                    )
                    attempt_result = {
                        "attempt": attempt,
                        "status": "model_error",
                        "failure_stage": "extract_source",
                        "error": str(exc),
                        "prompt_sha256": sha256_text(prompt),
                        "prompt_chars": len(prompt),
                        **model_metrics,
                        "oracle_wall_time_seconds": None,
                        "attempt_wall_time_seconds": round(time.perf_counter() - attempt_started, 6),
                    }
                    (attempt_out / "result.json").write_text(
                        json.dumps(attempt_result, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    attempts.append(attempt_result)
                    if attempt == args.repair_attempts:
                        break
                    retry_context = next_retry_context
                    continue

                oracle_started = time.perf_counter()
                completed = run_oracle(case_dir, candidate_path, attempt_out / "work")
                oracle_wall_time = round(time.perf_counter() - oracle_started, 6)
                next_retry_context = (
                    oracle_retry_context(completed, candidate_source)
                    if completed.returncode != 0 and attempt < args.repair_attempts
                    else None
                )
                attempt_result = {
                    "attempt": attempt,
                    "status": "pass" if completed.returncode == 0 else "fail",
                    "failure_stage": oracle_failure_stage(completed),
                    "candidate": str(candidate_path),
                    "oracle_stdout": completed.stdout,
                    "oracle_stderr": completed.stderr,
                    "oracle_returncode": completed.returncode,
                    "prompt_sha256": sha256_text(prompt),
                    "prompt_chars": len(prompt),
                    **model_metrics,
                    "oracle_wall_time_seconds": oracle_wall_time,
                    "attempt_wall_time_seconds": round(time.perf_counter() - attempt_started, 6),
                }
                (attempt_out / "result.json").write_text(
                    json.dumps(attempt_result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                attempts.append(attempt_result)
                if completed.returncode == 0:
                    break
                retry_context = next_retry_context

            last_attempt = attempts[-1]
            final_result = {
                "case": case_dir.name,
                **last_attempt,
                "attempts": attempts,
                "mode": args.mode,
                "model": args.model,
                **prompt_info,
            }
            final_result["cost"] = aggregate_attempt_cost(attempts)
            (case_out / "result.json").write_text(json.dumps(final_result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            summary.append(final_result)
            continue
        else:
            candidate_path = args.candidate.resolve()

        oracle_started = time.perf_counter()
        completed = run_oracle(case_dir, candidate_path, case_out / "work")
        oracle_wall_time = round(time.perf_counter() - oracle_started, 6)
        result = {
            "case": case_dir.name,
            "status": "pass" if completed.returncode == 0 else "fail",
            "failure_stage": oracle_failure_stage(completed),
            "candidate": str(candidate_path),
            "oracle_stdout": completed.stdout,
            "oracle_stderr": completed.stderr,
            "oracle_returncode": completed.returncode,
            "mode": args.mode,
            "model": args.model,
            "oracle_wall_time_seconds": oracle_wall_time,
            **prompt_info,
        }
        (case_out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary.append(result)

    passed = sum(1 for item in summary if item.get("status") == "pass")
    result_summary = {
        "mode": args.mode,
        "total": len(summary),
        "passed": passed,
        "cost": aggregate_attempt_cost(
            [
                attempt
                for result in summary
                if isinstance((attempts := result.get("attempts")), list)
                for attempt in attempts
            ]
        ),
        "policy_checkpoints": repair_policy_checkpoints(
            summary,
            args.repair_attempts if args.candidate is None and not args.prompt_only else None,
        ),
        "run_metadata": metadata,
        "results": summary,
    }
    (run_dir / "summary.json").write_text(json.dumps(result_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result_summary, indent=2, sort_keys=True))
    if args.prompt_only:
        return 0
    return 0 if passed == len(summary) else 1


if __name__ == "__main__":
    raise SystemExit(main())
