#!/usr/bin/env python3
"""Run or smoke-test the bpfix-test LLM repair suite."""

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
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "http://127.0.0.1:18080/v1"
DEFAULT_MODEL = "Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M"
MODES = ["source-only", "raw", "trimmed-raw", "bpfix"]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def discover_cases(root: Path) -> list[Path]:
    cases_root = root / "bpfix-test" / "cases"
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
            "model_file": model_file_metadata(args.model_path, args.model_sha256),
            "llama_cpp": llama_cpp_metadata(args.llama_cpp_dir),
            "server": server_model_metadata(args.base_url),
        },
        "case_selection": {
            "split": split_metadata(args),
            "case_overrides": args.case or [],
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

    return f"""You are fixing one eBPF verifier rejection.

Return only one complete replacement C source file in a fenced ```c block.
Do not explain. Do not output a diff. Preserve the intended packet/helper
semantics; do not remove the program, maps, SEC() section, or license.
{diagnostic_guidance}

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


def append_retry_context(prompt: str, retry_context: str | None) -> str:
    if retry_context is None:
        return prompt
    return f"{prompt}\n\nRetry context:\n{retry_context}\n"


def call_openai_compatible(
    *,
    base_url: str,
    api_key: str,
    model: str,
    prompt: str,
    timeout: float,
    max_tokens: int,
    temperature: float,
) -> str:
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
    return str(payload["choices"][0]["message"]["content"])


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
    parser.add_argument("--results-dir", type=Path, default=repo_root() / "bpfix-test" / "results")
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
    return parser.parse_args(argv)


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
        base_prompt = build_prompt(case_dir, args.mode)
        (case_out / "prompt.txt").write_text(base_prompt, encoding="utf-8")
        prompt_info = {
            "prompt_sha256": sha256_text(base_prompt),
            "prompt_chars": len(base_prompt),
            "source_chars": len((case_dir / "buggy.bpf.c").read_text(encoding="utf-8")),
            "diagnostic_chars": len(diagnostic_input(case_dir, args.mode)[1]),
        }

        if args.prompt_only:
            summary.append({"case": case_dir.name, "status": "prompt_written", **prompt_info})
            continue

        if args.candidate is None:
            retry_context = None
            attempts: list[dict[str, Any]] = []
            final_result: dict[str, Any] | None = None
            for attempt in range(1, args.repair_attempts + 1):
                attempt_out = case_out / f"attempt-{attempt}"
                attempt_out.mkdir(parents=True, exist_ok=True)
                prompt = append_retry_context(base_prompt, retry_context)
                (attempt_out / "prompt.txt").write_text(prompt, encoding="utf-8")
                try:
                    response = call_openai_compatible(
                        base_url=args.base_url,
                        api_key=api_key,
                        model=args.model,
                        prompt=prompt,
                        timeout=args.timeout,
                        max_tokens=args.max_tokens,
                        temperature=args.temperature,
                    )
                    (attempt_out / "response.txt").write_text(response, encoding="utf-8")
                except (
                    json.JSONDecodeError,
                    urllib.error.URLError,
                    TimeoutError,
                    KeyError,
                    ConnectionError,
                    http.client.HTTPException,
                ) as exc:
                    final_result = {
                        "case": case_dir.name,
                        "status": "model_error",
                        "failure_stage": "model_call",
                        "error": str(exc),
                        "attempt": attempt,
                        "attempts": attempts,
                        "mode": args.mode,
                        "model": args.model,
                        **prompt_info,
                    }
                    break
                try:
                    candidate_source = extract_source(response)
                    candidate_path = attempt_out / "candidate.bpf.c"
                    candidate_path.write_text(candidate_source, encoding="utf-8")
                except ValueError as exc:
                    attempt_result = {
                        "attempt": attempt,
                        "status": "model_error",
                        "failure_stage": "extract_source",
                        "error": str(exc),
                    }
                    attempts.append(attempt_result)
                    final_result = {
                        "case": case_dir.name,
                        **attempt_result,
                        "attempts": attempts,
                        "mode": args.mode,
                        "model": args.model,
                        **prompt_info,
                    }
                    break

                completed = run_oracle(case_dir, candidate_path, attempt_out / "work")
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
                }
                (attempt_out / "result.json").write_text(
                    json.dumps(attempt_result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                attempts.append(attempt_result)
                if completed.returncode == 0:
                    final_result = {
                        "case": case_dir.name,
                        **attempt_result,
                        "attempts": attempts,
                        "mode": args.mode,
                        "model": args.model,
                        **prompt_info,
                    }
                    break
                retry_context = oracle_retry_context(completed, candidate_source)

            if final_result is None:
                last_attempt = attempts[-1]
                final_result = {
                    "case": case_dir.name,
                    **last_attempt,
                    "attempts": attempts,
                    "mode": args.mode,
                    "model": args.model,
                    **prompt_info,
                }
            (case_out / "result.json").write_text(json.dumps(final_result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            summary.append(final_result)
            continue
        else:
            candidate_path = args.candidate.resolve()

        completed = run_oracle(case_dir, candidate_path, case_out / "work")
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
            **prompt_info,
        }
        (case_out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary.append(result)

    passed = sum(1 for item in summary if item.get("status") == "pass")
    result_summary = {
        "mode": args.mode,
        "total": len(summary),
        "passed": passed,
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
