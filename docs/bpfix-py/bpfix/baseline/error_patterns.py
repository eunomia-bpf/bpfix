"""Regex matching and tail-window selection for the message-only baseline."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re

import yaml

DEFAULT_CATALOG_PATH = Path(__file__).resolve().parents[1] / "catalogs" / "error_catalog.yaml"
TAIL_SCAN_LINES = 80

INSTRUCTION_RE = re.compile(r"^(?P<idx>\d+):\s+\([0-9a-f]{2}\)", flags=re.IGNORECASE)
REGISTER_STATE_RE = re.compile(r"^R\d+(?:_[a-z]+)?=", flags=re.IGNORECASE)
SUMMARY_RE = re.compile(
    r"^(processed|max_states|peak_states|mark_read|verification time|stack depth)\b",
    flags=re.IGNORECASE,
)
BACKTRACK_RE = re.compile(
    r"^(last_idx|first_idx|parent didn't have|regs=\d+ stack=|from \d+ to \d+:|mark_precise:)\b",
    flags=re.IGNORECASE,
)
COMMENT_RE = re.compile(r"^;", flags=re.IGNORECASE)
ERROR_HINT_RE = re.compile(
    r"\b("
    r"invalid|unknown|unreleased|unbounded|expected|cannot|too many|"
    r"loop is not bounded|back-edge|complexity limit|out of bounds|"
    r"pointer comparison prohibited|must be|not allowed|warning|bug|"
    r"unsupported|malformed|sleepable|operation not supported"
    r")\b",
    flags=re.IGNORECASE,
)
SOURCE_LOCATION_SUFFIX_RE = re.compile(
    r"@\s*(?P<file>.+?):(?P<line>\d+)(?::(?P<column>\d+))?\s*$"
)
BTF_PROBE_NOISE_RE = re.compile(
    r"reference type\('UNKNOWN\s*'\)\s+size cannot be determined",
    flags=re.IGNORECASE,
)
PROCESSED_LIMIT_RE = re.compile(
    r"processed\s+(?P<count>\d+)\s+insns\s+\(limit\s+(?P<limit>\d+)\)",
    flags=re.IGNORECASE,
)
STACK_DEPTH_RE = re.compile(r"stack depth\s+(?P<depth>\d+)", flags=re.IGNORECASE)
PREFIX_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^libbpf:\s+prog\s+'.*?':\s+", flags=re.IGNORECASE),
    re.compile(r"^libbpf:\s+", flags=re.IGNORECASE),
    re.compile(r"^verifier error:\s+", flags=re.IGNORECASE),
    re.compile(r"^load program:\s+", flags=re.IGNORECASE),
    re.compile(r"^permission denied:\s+", flags=re.IGNORECASE),
)


@dataclass(frozen=True)
class ErrorPattern:
    error_id: str
    failure_class: str
    short_name: str
    title: str
    likely_obligation: str | None
    example_fix_actions: tuple[str, ...]
    verifier_messages: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class MatchedPattern:
    pattern: ErrorPattern
    matched_regex: str


@dataclass(frozen=True)
class SourceLocation:
    path: str | None
    line: int | None
    column: int | None
    snippet: str | None


@dataclass(frozen=True)
class DiagnosticContext:
    error_line: str
    instruction_index: int | None
    matched_pattern: MatchedPattern | None
    matched_line_index: int | None
    source_location: SourceLocation | None
    evidence_lines: tuple[str, ...]
    selection_reason: str


_SYNTHETIC_LIMIT_PATTERN = ErrorPattern(
    error_id="BPFIX-E018",
    failure_class="verifier_limit",
    short_name="verifier_analysis_budget_limit",
    title="Verifier rejects the proof shape due to bounded analysis or complexity limits",
    likely_obligation="BPFIX-O018",
    example_fix_actions=("REDUCE_CONTROL_FLOW_BRANCHING", "SPLIT_PROGRAM_INTO_HELPERS"),
    verifier_messages=(),
)


def normalize_log_line(line: str) -> str:
    """Strip wrapper prefixes so message regexes see the verifier text itself."""

    normalized = line.strip()
    while normalized.startswith(":"):
        normalized = normalized[1:].lstrip()
    for prefix in PREFIX_PATTERNS:
        normalized = prefix.sub("", normalized)
    return normalized


def is_noise_line(line: str) -> bool:
    """Reject trace-only lines that are not standalone verifier messages."""

    normalized = normalize_log_line(line)
    if not normalized:
        return True
    return bool(
        COMMENT_RE.match(normalized)
        or INSTRUCTION_RE.match(normalized)
        or REGISTER_STATE_RE.match(normalized)
        or SUMMARY_RE.match(normalized)
        or BACKTRACK_RE.match(normalized)
    )


def looks_like_error_message(line: str) -> bool:
    normalized = normalize_log_line(line)
    if is_noise_line(normalized):
        return False
    return bool(ERROR_HINT_RE.search(normalized))


def _regex_specificity(pattern: str) -> int:
    return sum(1 for char in pattern if char.isalnum())


@lru_cache(maxsize=4)
def load_error_patterns(catalog_path: str | None = None) -> tuple[ErrorPattern, ...]:
    path = Path(catalog_path) if catalog_path else DEFAULT_CATALOG_PATH
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    patterns: list[ErrorPattern] = []
    for entry in payload.get("error_types", []):
        patterns.append(
            ErrorPattern(
                error_id=entry["error_id"],
                failure_class=entry["taxonomy_class"],
                short_name=entry.get("short_name", entry["error_id"]),
                title=entry["title"],
                likely_obligation=entry.get("likely_obligation"),
                example_fix_actions=tuple(entry.get("example_fix_actions", [])),
                verifier_messages=tuple(
                    re.compile(message, flags=re.IGNORECASE)
                    for message in entry.get("verifier_messages", [])
                ),
            )
        )
    return tuple(patterns)


def match_error_patterns(
    message: str,
    *,
    catalog_path: str | None = None,
) -> tuple[MatchedPattern, ...]:
    normalized = normalize_log_line(message)
    matches: list[MatchedPattern] = []
    for pattern in load_error_patterns(catalog_path):
        for regex in pattern.verifier_messages:
            if regex.search(normalized):
                matches.append(MatchedPattern(pattern=pattern, matched_regex=regex.pattern))
    return tuple(
        sorted(
            matches,
            key=lambda item: _regex_specificity(item.matched_regex),
            reverse=True,
        )
    )


def match_error_pattern(
    message: str,
    *,
    catalog_path: str | None = None,
) -> MatchedPattern | None:
    matches = match_error_patterns(message, catalog_path=catalog_path)
    return matches[0] if matches else None


def _synthetic_limit_match(line: str) -> MatchedPattern | None:
    normalized = normalize_log_line(line)
    stack_match = STACK_DEPTH_RE.match(normalized)
    if stack_match is not None and int(stack_match.group("depth")) >= 256:
        return MatchedPattern(pattern=_SYNTHETIC_LIMIT_PATTERN, matched_regex=STACK_DEPTH_RE.pattern)

    processed_match = PROCESSED_LIMIT_RE.search(normalized)
    if processed_match is None:
        return None

    count = int(processed_match.group("count"))
    limit = int(processed_match.group("limit"))
    if count >= 100_000 or (limit > 0 and count / limit >= 0.45):
        return MatchedPattern(
            pattern=_SYNTHETIC_LIMIT_PATTERN,
            matched_regex=PROCESSED_LIMIT_RE.pattern,
        )
    return None


def _candidate_score(
    message: str,
    matched_pattern: MatchedPattern | None,
    *,
    relative_index: int,
    total_lines: int,
) -> float:
    lowered = message.lower()
    score = relative_index / max(total_lines, 1)

    if matched_pattern is not None:
        score += 100.0
        score += _regex_specificity(matched_pattern.matched_regex) / 20.0
        if matched_pattern.pattern.error_id == "BPFIX-E018":
            score += 20.0
    elif looks_like_error_message(message):
        score += 25.0

    if "type=" in lowered and "expected=" in lowered:
        score += 40.0
    if "invalid bpf_context access" in lowered:
        score += 35.0
    if "unknown func" in lowered or "cannot be called from callback" in lowered:
        score += 30.0
    if "invalid btf" in lowered or "reference type('unknown" in lowered:
        score += 30.0
    if "btf_vmlinux is malformed" in lowered or "jit does not support calling kfunc" in lowered:
        score += 35.0
    if BTF_PROBE_NOISE_RE.search(message):
        score -= 45.0
    if lowered.startswith("stack depth "):
        score += 35.0
    if lowered.startswith("processed "):
        score += 25.0
    if "loop is not bounded" in lowered or "back-edge" in lowered:
        score += 25.0
    if "unbounded" in lowered or "value is outside of the" in lowered:
        score += 20.0
    if "memory, len pair leads to invalid memory access" in lowered:
        score -= 15.0
    if "offset is outside of the packet" in lowered:
        score -= 4.0

    return score


def _parse_source_annotation(line: str) -> SourceLocation | None:
    raw = line.strip()
    while raw.startswith(":"):
        raw = raw[1:].lstrip()
    if not raw.startswith(";"):
        return None

    annotation = raw[1:].strip()
    if not annotation:
        return None

    location = SOURCE_LOCATION_SUFFIX_RE.search(annotation)
    if location is None:
        return SourceLocation(path=None, line=None, column=None, snippet=annotation)

    snippet = annotation[: location.start()].strip() or None
    column = location.group("column")
    return SourceLocation(
        path=location.group("file"),
        line=int(location.group("line")),
        column=int(column) if column is not None else None,
        snippet=snippet,
    )


def _find_nearest_source_location(lines: list[str], start_idx: int) -> SourceLocation | None:
    instructions_seen = 0
    lower_bound = max(0, start_idx - 18)

    for idx in range(start_idx, lower_bound - 1, -1):
        location = _parse_source_annotation(lines[idx])
        if location is not None and (location.path is not None or location.snippet is not None):
            return location
        if idx != start_idx and INSTRUCTION_RE.match(normalize_log_line(lines[idx])):
            instructions_seen += 1
            if instructions_seen >= 5:
                break
    return None


def _collect_evidence_lines(lines: list[str], matched_idx: int) -> tuple[str, ...]:
    start = max(0, matched_idx - 3)
    evidence: list[str] = []
    for idx in range(start, matched_idx + 1):
        raw = lines[idx].strip()
        normalized = normalize_log_line(raw)
        if not raw:
            continue
        if idx == matched_idx:
            evidence.append(normalized or raw)
            continue
        if raw.lstrip().startswith((";", ":;")):
            evidence.append(raw.lstrip())
            continue
        if INSTRUCTION_RE.match(normalized):
            evidence.append(normalized)
            continue
        if looks_like_error_message(normalized):
            evidence.append(normalized)

    deduped: list[str] = []
    for line in evidence:
        if line not in deduped:
            deduped.append(line)
    return tuple(deduped)


def extract_diagnostic_context(
    verifier_log: str,
    *,
    catalog_path: str | None = None,
) -> DiagnosticContext:
    """Select the most diagnostic verifier line from the tail of the log."""

    lines = [line.rstrip() for line in verifier_log.splitlines() if line.strip()]
    if not lines:
        return DiagnosticContext(
            error_line="",
            instruction_index=None,
            matched_pattern=None,
            matched_line_index=None,
            source_location=None,
            evidence_lines=(),
            selection_reason="empty_log",
        )

    window_start = max(0, len(lines) - TAIL_SCAN_LINES)
    tail = lines[window_start:]
    best_context: tuple[float, int, str, MatchedPattern | None] | None = None
    fallback_idx: int | None = None

    for relative_idx, raw_line in enumerate(tail):
        absolute_idx = window_start + relative_idx
        normalized = normalize_log_line(raw_line)
        if not normalized:
            continue
        if not is_noise_line(normalized):
            fallback_idx = absolute_idx

        matched = match_error_pattern(normalized, catalog_path=catalog_path)
        synthetic = _synthetic_limit_match(normalized)
        if synthetic is not None:
            matched = synthetic

        if matched is None and not looks_like_error_message(normalized):
            continue

        score = _candidate_score(
            normalized,
            matched,
            relative_index=relative_idx,
            total_lines=len(tail),
        )
        if best_context is None or score > best_context[0] or (
            score == best_context[0] and absolute_idx > best_context[1]
        ):
            best_context = (score, absolute_idx, normalized, matched)

    if best_context is not None:
        _, matched_idx, error_line, matched_pattern = best_context
        return DiagnosticContext(
            error_line=error_line,
            instruction_index=find_nearest_instruction_index(lines, matched_idx),
            matched_pattern=matched_pattern,
            matched_line_index=matched_idx,
            source_location=_find_nearest_source_location(lines, matched_idx),
            evidence_lines=_collect_evidence_lines(lines, matched_idx),
            selection_reason="best_tail_candidate",
        )

    if fallback_idx is not None:
        fallback_line = normalize_log_line(lines[fallback_idx])
        return DiagnosticContext(
            error_line=fallback_line,
            instruction_index=find_nearest_instruction_index(lines, fallback_idx),
            matched_pattern=None,
            matched_line_index=fallback_idx,
            source_location=_find_nearest_source_location(lines, fallback_idx),
            evidence_lines=_collect_evidence_lines(lines, fallback_idx),
            selection_reason="fallback_non_noise_tail_line",
        )

    final_idx = len(lines) - 1
    final_line = normalize_log_line(lines[final_idx])
    return DiagnosticContext(
        error_line=final_line,
        instruction_index=find_nearest_instruction_index(lines, final_idx),
        matched_pattern=None,
        matched_line_index=final_idx,
        source_location=_find_nearest_source_location(lines, final_idx),
        evidence_lines=_collect_evidence_lines(lines, final_idx),
        selection_reason="fallback_last_line",
    )
def find_nearest_instruction_index(lines: list[str], start_idx: int) -> int | None:
    for idx in range(start_idx, -1, -1):
        match = INSTRUCTION_RE.match(normalize_log_line(lines[idx]))
        if match is not None:
            return int(match.group("idx"))
    return None
