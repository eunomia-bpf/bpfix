"""Replay one benchmark case and parse verifier rejection logs."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROCESSED_RE = re.compile(r"\bprocessed\s+\d+\s+insns\b", re.IGNORECASE)
INSN_RE = re.compile(r"^\s*(\d+):\s*(?:[.0-9A-Za-z]+\s+)?\([0-9a-fA-F]{2,3}\)")
NOISE_RE = re.compile(
    r"^\s*(?:"
    r"R\d+(?:_w)?=|"
    r"[a-z]\d(?:_w)?=|"
    r"from\s+\d+\s+to\s+\d+|"
    r"verification\s+time|"
    r"stack\s+depth|"
    r"processed\s+\d+\s+insns|"
    r"mark_precise|"
    r"last_idx|"
    r"parent\s+didn't\s+have|"
    r";|"
    r"$"
    r")",
    re.IGNORECASE,
)
MAX_CAPTURE_BYTES = 8_000_000


@dataclass
class CommandResult:
    command: str
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def combined_output(self) -> str:
        chunks = []
        if self.stdout:
            chunks.append(self.stdout)
        if self.stderr:
            chunks.append(self.stderr)
        return "\n".join(chunks)


@dataclass
class ParsedVerifierLog:
    terminal_error: str | None
    rejected_insn_idx: int | None
    log_quality: str
    source: str


@dataclass
class ReplayResult:
    build: CommandResult
    load: CommandResult
    parsed_log: ParsedVerifierLog
    verifier_log_captured: str | None


def run_shell_command(command: str, cwd: Path, timeout_sec: int) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            command=command,
            returncode=None,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
        )
    return CommandResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def parse_verifier_log(text: str, source: str = "output") -> ParsedVerifierLog:
    if not text or not text.strip():
        return ParsedVerifierLog(None, None, "empty", source)

    lines = text.splitlines()
    terminal_line_index = _terminal_error_line_index(lines)
    terminal_error = None
    if terminal_line_index is not None:
        terminal_error = _clean_terminal_error(lines[terminal_line_index])

    search_end = terminal_line_index
    if search_end is None:
        search_end = _first_processed_line_index(lines)
    rejected_insn_idx = _last_instruction_index(lines, search_end)
    if rejected_insn_idx is None:
        rejected_insn_idx = _fallback_instruction_index(lines, search_end, terminal_error)

    if terminal_error and rejected_insn_idx is not None:
        quality = "trace_rich"
    elif terminal_error:
        quality = "message_only"
    else:
        quality = "no_terminal_error"

    return ParsedVerifierLog(
        terminal_error=terminal_error,
        rejected_insn_idx=rejected_insn_idx,
        log_quality=quality,
        source=source,
    )


def replay_case(case_dir: Path, case_data: dict[str, Any], timeout_sec: int = 30) -> ReplayResult:
    reproducer = case_data.get("reproducer") or {}
    build_command = _required_string(reproducer, "build_command")
    load_command = _required_string(reproducer, "load_command")

    capture = case_data.get("capture") or {}
    candidate_paths = [case_dir / "replay-verifier.log", case_dir / "verifier_log_captured.txt"]
    verifier_log = capture.get("verifier_log")
    if isinstance(verifier_log, str) and verifier_log:
        candidate_paths.append(case_dir / verifier_log)
    before_mtimes = {
        path: path.stat().st_mtime_ns if path.exists() else None
        for path in candidate_paths
    }

    build = run_shell_command(build_command, case_dir, timeout_sec)
    load = run_shell_command(load_command, case_dir, timeout_sec)

    captured_text = None
    captured_source = None
    for candidate_path in candidate_paths:
        captured_text = _read_fresh_capture(candidate_path, before_mtimes[candidate_path])
        if captured_text:
            captured_source = candidate_path.name
            break
    output_text = load.combined_output

    parsed = parse_verifier_log(output_text, source="load_output")
    if not parsed.terminal_error and captured_text:
        parsed = parse_verifier_log(captured_text, source=captured_source or "fresh_verifier_log")
    elif captured_text and parsed.log_quality != "trace_rich":
        captured_parsed = parse_verifier_log(captured_text, source=captured_source or "fresh_verifier_log")
        if _quality_rank(captured_parsed.log_quality) > _quality_rank(parsed.log_quality):
            parsed = captured_parsed

    return ReplayResult(
        build=build,
        load=load,
        parsed_log=parsed,
        verifier_log_captured=captured_text,
    )


def _required_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing required reproducer.{key}")
    return value


def _read_fresh_capture(path: Path, before_mtime: int | None) -> str | None:
    if not path.exists():
        return None
    current_mtime = path.stat().st_mtime_ns
    if before_mtime is not None and current_mtime == before_mtime:
        return None
    if path.stat().st_size > MAX_CAPTURE_BYTES:
        with path.open("rb") as handle:
            handle.seek(-MAX_CAPTURE_BYTES, 2)
            text = handle.read().decode("utf-8", errors="replace")
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
    return text if text.strip() else None


def _quality_rank(quality: str) -> int:
    return {"empty": 0, "no_terminal_error": 1, "message_only": 2, "trace_rich": 3}.get(quality, 0)


def _first_processed_line_index(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if PROCESSED_RE.search(line):
            return index
    return None


def _terminal_error_line_index(lines: list[str]) -> int | None:
    processed_index = _first_processed_line_index(lines)
    if processed_index is not None:
        for index in range(processed_index - 1, -1, -1):
            if _looks_like_terminal_error(lines[index]):
                return index

    for index in range(len(lines) - 1, -1, -1):
        if _looks_like_terminal_error(lines[index]):
            return index
    return None


def _looks_like_terminal_error(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if INSN_RE.match(stripped):
        return False
    if PROCESSED_RE.search(stripped):
        return False
    if NOISE_RE.match(stripped):
        return False
    lower = stripped.lower()
    if lower.startswith(("libbpf:", "error:", "failed to", "make:", "clang", "ld.lld")):
        return False
    error_terms = (
        "invalid",
        "unbounded",
        "not allowed",
        "prohibited",
        "permission",
        "misaligned",
        "unreleased",
        "too large",
        "possibly null",
        "null pointer",
        "out of bounds",
        "min value is negative",
        "reference leak",
        "unbounded memory access",
        "has no",
        "has to",
        "only read from",
        "does not allow",
        "does not support",
        "expected",
        "must",
        "may",
        "arg#",
        "access beyond",
        "dereference",
        "cannot",
        "missing btf func_info",
        "not an exit or jmp",
        "not pointing to valid",
        "makes pkt pointer",
        "!read_ok",
        "infinite loop",
        "math between",
        "type=",
        "verifier log",
        "unknown opcode",
        "should have been",
    )
    return any(term.lower() in lower for term in error_terms)


def _clean_terminal_error(line: str) -> str:
    stripped = line.strip()
    stripped = re.sub(r"^\s*(?:libbpf:\s*)?(?:verifier log:\s*)", "", stripped, flags=re.IGNORECASE)
    return stripped.strip()


def _last_instruction_index(lines: list[str], search_end: int | None) -> int | None:
    end = len(lines) if search_end is None else max(search_end, 0)
    last: int | None = None
    for line in lines[:end]:
        match = INSN_RE.match(line)
        if match:
            last = int(match.group(1))
    return last


def _fallback_instruction_index(lines: list[str], search_end: int | None, terminal_error: str | None) -> int | None:
    if not terminal_error:
        return None
    end = len(lines) if search_end is None else max(search_end, 0)
    window = lines[:end]
    if "unknown opcode" in terminal_error.lower():
        for line in reversed(window):
            match = re.match(r"^\s*func#\d+\s+@(\d+)\s*$", line)
            if match:
                return int(match.group(1))
    return None
