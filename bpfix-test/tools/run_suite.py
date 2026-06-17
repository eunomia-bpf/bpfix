#!/usr/bin/env python3
"""Run or smoke-test the bpfix-test LLM repair suite."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
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


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def discover_cases(root: Path) -> list[Path]:
    cases_root = root / "bpfix-test" / "cases"
    return sorted(case for case in cases_root.iterdir() if (case / "buggy.bpf.c").exists())


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


def run_metadata(args: argparse.Namespace, root: Path) -> dict[str, object]:
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
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
    }


def build_prompt(case_dir: Path, mode: str) -> str:
    source = (case_dir / "buggy.bpf.c").read_text(encoding="utf-8")
    if mode == "raw":
        diagnostic_label = "raw verifier log"
        diagnostic = (case_dir / "verifier.log").read_text(encoding="utf-8")
        diagnostic_guidance = ""
    else:
        diagnostic_label = "BPFix structured diagnostic JSON"
        diagnostic = (case_dir / "structured.json").read_text(encoding="utf-8")
        diagnostic_guidance = """
Use the structured diagnostic fields directly:
- `source_span` is the verifier-rejected operation to repair.
- `related_spans` are supporting proof context, not necessarily the only edits.
- `required_proof` and `help` are constraints the replacement source must satisfy.
- If `help` says an operation must not remain or must be rewritten, do not leave
  that operation in the replacement source, even if it appears unused.
"""

    return f"""You are fixing one eBPF verifier rejection.

Return only one complete replacement C source file in a fenced ```c block.
Do not explain. Do not output a diff. Preserve the intended packet/helper
semantics; do not remove the program, maps, SEC() section, or license.
{diagnostic_guidance}

Case: {case_dir.name}

Source file:
```c
{source}
```

{diagnostic_label}:
```text
{diagnostic}
```
"""


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


def smoke_case(case_dir: Path) -> dict[str, object]:
    missing = [
        name
        for name in ["buggy.bpf.c", "verifier.log", "structured.json", "test.py"]
        if not (case_dir / name).exists()
    ]
    report: dict[str, object] = {"case": case_dir.name, "missing": missing, "passed": False}
    if missing:
        return report
    try:
        json.loads((case_dir / "structured.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report["structured_json_error"] = str(exc)
        return report

    completed = run(
        [
            sys.executable,
            str(case_dir / "test.py"),
            "--source",
            str(case_dir / "buggy.bpf.c"),
            "--expect-reject",
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
    parser.add_argument("--mode", choices=["raw", "structured"], default="raw")
    parser.add_argument("--smoke", action="store_true", help="Validate fixtures and buggy rejection only.")
    parser.add_argument("--prompt-only", action="store_true", help="Write prompts without calling a model.")
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
    wanted_set = set(wanted)
    selected = [case for case in cases if case.name in wanted_set]
    missing = wanted_set - {case.name for case in selected}
    if missing:
        raise SystemExit(f"unknown case(s): {', '.join(sorted(missing))}")
    return selected


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = repo_root()
    cases = select_cases(root, args.case)

    if args.smoke:
        reports = [smoke_case(case) for case in cases]
        print(json.dumps({"smoke": reports}, indent=2, sort_keys=True))
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
        prompt = build_prompt(case_dir, args.mode)
        (case_out / "prompt.txt").write_text(prompt, encoding="utf-8")
        prompt_info = {
            "prompt_sha256": sha256_text(prompt),
            "prompt_chars": len(prompt),
            "source_chars": len((case_dir / "buggy.bpf.c").read_text(encoding="utf-8")),
            "diagnostic_chars": len(
                (case_dir / ("verifier.log" if args.mode == "raw" else "structured.json")).read_text(
                    encoding="utf-8"
                )
            ),
        }

        if args.prompt_only:
            summary.append({"case": case_dir.name, "status": "prompt_written", **prompt_info})
            continue

        if args.candidate is None:
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
                (case_out / "response.txt").write_text(response, encoding="utf-8")
                candidate_source = extract_source(response)
                candidate_path = case_out / "candidate.bpf.c"
                candidate_path.write_text(candidate_source, encoding="utf-8")
            except (ValueError, urllib.error.URLError, TimeoutError, KeyError) as exc:
                result = {"case": case_dir.name, "status": "model_error", "error": str(exc), **prompt_info}
                (case_out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
                summary.append(result)
                continue
        else:
            candidate_path = args.candidate.resolve()

        completed = run_oracle(case_dir, candidate_path, case_out / "work")
        result = {
            "case": case_dir.name,
            "status": "pass" if completed.returncode == 0 else "fail",
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
