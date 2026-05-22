"""Parse raw eBPF verifier logs into stable, catalog-backed diagnostic signals."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

ERROR_LINE_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    (
        re.compile(
            r"\binvalid\b|\bunknown\b|unreleased|too many|\bwarning\b|\bbug\b|loop is not bounded|back-edge|complexity limit",
            flags=re.IGNORECASE,
        ),
        5,
    ),
    (
        re.compile(
            "|".join(
                (
                    r"expected an initialized",
                    r"expected uninitialized",
                    r"unacquired reference",
                    r"dynptr",
                    r"irq flag",
                    r"misaligned stack access",
                    r"!read_ok",
                    r"must be referenced",
                    r"trusted",
                    r"pointer type .* must point",
                    r"type=.* expected=.*",
                    r"arg#?\d+",
                    r"reference type\('unknown '\)",
                    r"invalid btf",
                    r"missing btf func_info",
                    r"only read from bpf_array is supported",
                    r"function calls are not allowed",
                    r"cannot call exception cb directly",
                    r"exception cb only supports single integer argument",
                    r"attach to unsupported member",
                    r"unbounded memory access",
                    r"bpf program is too large",
                )
            ),
            flags=re.IGNORECASE,
        ),
        4,
    ),
)
INSTRUCTION_LINE_RE = re.compile(r"^\d+: \([0-9a-f]{2}\)", flags=re.IGNORECASE)
# Matches the spurious BTF probe line emitted by the verifier when it tries to
# resolve a kfunc/helper argument type at the start of a pass.  This line is
# NOT the root-cause error for dynptr/iterator/kfunc protocol violations — the
# actual error (e.g. "expected an initialized iter_num") appears later.  We
# give it a strong negative adjustment so it never beats the real error line.
BTF_PROBE_NOISE_RE = re.compile(
    r"reference type\('UNKNOWN\s*'\)\s+size cannot be determined",
    flags=re.IGNORECASE,
)
EXACT_VERIFIER_SYMPTOM_RE = re.compile(
    "|".join(
        (
            r"invalid access to (?:packet|map value)",
            r"invalid mem access",
            r"invalid bpf_context access",
            r"offset is outside of the packet",
            r"pointer comparison prohibited",
            r"pointer arithmetic on .* prohibited",
            r"expected (?:an )?initialized irq flag as arg#0",
            r"expected uninitialized irq flag as arg#0",
            r"arg#\d+\s+arg#\d+\s+memory,\s+len pair leads to invalid memory access",
            r"unbounded memory access",
            r"the prog does not allow writes to packet data",
            r"number of funcs in func_info doesn't match(?: number of subprogs)?",
            r"failed to find kernel BTF type ID",
            r"\bInvalid name\b",
            r"pointer type .* must point",
            # scalar/range errors that appear alongside spurious BTF probe lines
            r"math between .* pointer and register with unbounded",
            r"min value is negative, either use unsigned or",
            # dynptr protocol violations — programmer used the dynptr API wrongly
            r"Expected (?:an )?initialized dynptr as arg #\d+",
            r"Expected a dynptr of type .* as arg #\d+",
            r"cannot overwrite referenced dynptr",
            r"cannot pass in dynptr at an offset",
            r"dynptr has to be at a constant offset",
            # iterator state-machine violations: source_bug, not environment/configuration
            r"expected (?:an )?(?:un)?initialized iter_\w+ as arg #\d+",
            r"arg#\d+ expected pointer to an iterator",
            # exception callback misuse — source_bug
            r"cannot call exception cb directly",
            r"exception cb only supports single integer argument",
        )
    ),
    flags=re.IGNORECASE,
)
SUMMARY_PREFIXES = (
    "processed ",
    "max_states",
    "peak_states",
    "mark_read",
    "verification time",
)
CATALOG_PREFIX_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^libbpf:\s+prog\s+'.*?':\s+", flags=re.IGNORECASE),
    re.compile(r"^libbpf:\s+", flags=re.IGNORECASE),
    re.compile(r"^R\d+\s+", flags=re.IGNORECASE),
    re.compile(r"^insn\s+\d+\s+", flags=re.IGNORECASE),
    re.compile(r"^\d+:\s+"),
    re.compile(r"^verifier error:\s+", flags=re.IGNORECASE),
    re.compile(r"^load program:\s+", flags=re.IGNORECASE),
    re.compile(r"^permission denied:\s+", flags=re.IGNORECASE),
)


@dataclass(slots=True)
class ParsedLog:
    """Normalized verifier log information ready for later extraction stages."""

    raw_log: str
    lines: list[str]
    error_line: str
    error_id: str | None
    taxonomy_class: str | None
    source_line: int | None
    catalog_confidence: str | None = None
    catalog_source: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class _CatalogMatch:
    error_id: str
    taxonomy_class: str
    confidence: str
    source: str


class VerifierLogParser:
    """Apply the initial error catalog and a few line-oriented heuristics."""

    def __init__(self, catalog_path: Path | None = None) -> None:
        self.catalog_path = catalog_path or (
            Path(__file__).resolve().parents[1] / "catalogs" / "error_catalog.yaml"
        )
        self._catalog = self._load_catalog()

    def _load_catalog(self) -> list[dict[str, Any]]:
        return _load_catalog_cached(str(self.catalog_path.resolve()))

    def parse(self, raw_log: str) -> ParsedLog:
        """Extract the likely error line, stable error ID, and supporting evidence."""

        lines = [line.rstrip() for line in raw_log.splitlines() if line.strip()]
        error_line = self._select_error_line(lines)
        catalog_match = self._match_catalog(lines, error_line)
        source_line = self._extract_source_line(lines)
        evidence = self._collect_evidence(lines)

        return ParsedLog(
            raw_log=raw_log,
            lines=lines,
            error_line=error_line,
            error_id=catalog_match.error_id if catalog_match is not None else None,
            taxonomy_class=catalog_match.taxonomy_class if catalog_match is not None else None,
            source_line=source_line,
            catalog_confidence=catalog_match.confidence if catalog_match is not None else None,
            catalog_source=catalog_match.source if catalog_match is not None else None,
            evidence=evidence,
        )

    def _select_error_line(self, lines: list[str]) -> str:
        best_line = ""
        best_score = -1

        for idx, line in enumerate(lines):
            normalized = line.strip()
            while normalized.startswith(":"):
                normalized = normalized[1:].lstrip()
            if not normalized:
                continue

            lowered = normalized.lower()
            score = 0
            for pattern, weight in ERROR_LINE_PATTERNS:
                if pattern.search(normalized):
                    score += weight

            if _is_specific_verifier_symptom(normalized):
                score += 7
            if BTF_PROBE_NOISE_RE.search(normalized):
                # This BTF probe failure is emitted before the main trace when
                # the verifier introspects kfunc/helper argument types.  For
                # dynptr, iterator, and kfunc protocol violations it is noise —
                # the real error line (e.g. "expected an initialized iter_num")
                # appears later.  Penalise strongly so the real error wins.
                score -= 8
            if INSTRUCTION_LINE_RE.match(normalized):
                score -= 4
            if normalized.startswith(";"):
                score -= 6
            if lowered.startswith(SUMMARY_PREFIXES):
                score -= 8
            if lowered.startswith("libbpf:") and any(
                _is_specific_verifier_symptom(later.strip())
                for later in lines[idx + 1 :]
                if later.strip()
            ):
                score -= 5
            if normalized.startswith(("R", "arg#")):
                score += 1

            if score >= best_score:
                best_score = score
                best_line = normalized

        if best_score > 0:
            return best_line
        return lines[-1] if lines else ""

    def _match_catalog(self, lines: list[str], error_line: str) -> _CatalogMatch | None:
        error_variants = _catalog_line_variants(error_line)
        error_variant_set = set(error_variants)
        all_variants = [
            variant
            for line in lines
            for variant in _catalog_line_variants(line)
        ]
        other_variants = [
            variant
            for variant in all_variants
            if variant not in error_variant_set
            and not _is_low_confidence_catalog_noise(variant)
        ]

        for confidence, source, candidates, primary_only in (
            ("high", "error_line_primary", error_variants, True),
            ("medium", "error_line_alternate", error_variants, False),
            ("low", "other_line_primary", other_variants, True),
            ("low", "other_line_alternate", other_variants, False),
        ):
            match = self._scan_catalog(
                candidates=candidates,
                confidence=confidence,
                source=source,
                primary_only=primary_only,
            )
            if match is not None:
                return match
        return None

    def _scan_catalog(
        self,
        candidates: list[str],
        confidence: str,
        source: str,
        primary_only: bool,
    ) -> _CatalogMatch | None:
        if not candidates:
            return None

        seen_candidates: set[str] = set()
        ordered_candidates = [
            candidate
            for candidate in candidates
            if candidate and not (candidate in seen_candidates or seen_candidates.add(candidate))
        ]
        for entry in self._catalog:
            patterns = entry.get("verifier_messages", [])
            if not patterns:
                continue
            candidate_patterns = patterns[:1] if primary_only else patterns[1:]
            for pattern in candidate_patterns:
                for candidate in ordered_candidates:
                    if re.match(pattern, candidate, flags=re.IGNORECASE):
                        return _CatalogMatch(
                            error_id=entry["error_id"],
                            taxonomy_class=entry["taxonomy_class"],
                            confidence=confidence,
                            source=source,
                        )
        return None

    def _extract_source_line(self, lines: list[str]) -> int | None:
        patterns = [
            re.compile(r";\s*line\s+(?P<line>\d+)"),
            re.compile(r"line\s+(?P<line>\d+):"),
        ]
        for line in lines:
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    return int(match.group("line"))
        return None

    def _collect_evidence(self, lines: list[str]) -> list[str]:
        evidence_tokens = (
            "R0",
            "R1",
            "R2",
            "stack",
            "packet",
            "helper",
            "loop",
            "reference",
            "dynptr",
            "irq",
            "btf",
            "map",
            "kptr",
            "trusted",
            "rcu",
            "arg#",
            "read_ok",
        )
        return [
            line
            for line in lines
            if any(token.lower() in line.lower() for token in evidence_tokens)
        ][:5]


def parse_log(raw_log: str, catalog_path: str | Path | None = None) -> ParsedLog:
    """Convenience wrapper matching the lightweight comparison-script API."""

    parser = VerifierLogParser(
        catalog_path=Path(catalog_path) if catalog_path is not None else None
    )
    return parser.parse(raw_log)


@lru_cache(maxsize=None)
def _load_catalog_cached(catalog_path: str) -> list[dict[str, Any]]:
    try:
        import yaml
    except ImportError:
        return []

    with Path(catalog_path).open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    return payload.get("error_types", [])


def parse_verifier_log(raw_log: str, catalog_path: str | Path | None = None) -> ParsedLog:
    """Backward-compatible alias used by corpus coverage scripts."""

    return parse_log(raw_log, catalog_path=catalog_path)


def _is_specific_verifier_symptom(line: str) -> bool:
    lowered = line.lower()
    if not line or line.startswith(";") or lowered.startswith(SUMMARY_PREFIXES):
        return False
    return EXACT_VERIFIER_SYMPTOM_RE.search(line) is not None


def _normalize_catalog_line(line: str) -> str:
    normalized = line.strip()
    while normalized.startswith(":"):
        normalized = normalized[1:].lstrip()
    return normalized


def _catalog_line_variants(line: str) -> list[str]:
    normalized = _normalize_catalog_line(line)
    if not normalized:
        return []

    variants = [normalized]
    queue = [normalized]
    seen = {normalized}
    while queue:
        current = queue.pop(0)
        for pattern in CATALOG_PREFIX_PATTERNS:
            candidate = pattern.sub("", current, count=1).lstrip()
            if candidate and candidate not in seen:
                seen.add(candidate)
                variants.append(candidate)
                queue.append(candidate)
    return variants


def _is_low_confidence_catalog_noise(line: str) -> bool:
    normalized = _normalize_catalog_line(line)
    return bool(normalized and BTF_PROBE_NOISE_RE.search(normalized))
