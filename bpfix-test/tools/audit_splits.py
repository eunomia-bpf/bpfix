#!/usr/bin/env python3
"""Audit bpfix-test split files and heldout contamination rules."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote
from urllib.parse import urlparse

import audit_cases
import run_suite


SCHEMA_VERSION = "bpfix.test.split-manifest/v1"
BUCKETS = {
    "proof_lifecycle",
    "source_object_correlation",
    "modern_bpf_protocol",
    "helper_memory_contract",
    "environment_config_boundary",
}
SOURCE_CATEGORIES = {
    "dev_calibration",
    "production_shaped_synthetic",
    "real_project_seed",
    "minimized_upstream_style",
}
PROG_TYPES = {"xdp", "tc", "tracepoint", "lsm", "cgroup", "perf_event", "socket_filter", "other"}
ORACLE_KINDS = {
    "compile",
    "verifier_load",
    "bpftool_prog_run",
    "attach_or_runtime",
    "environment_config",
    "custom_oracle",
    "helper_state",
    "proof_predicate",
}
BASE_CLEAN_ORACLE_KINDS = {"compile", "verifier_load"}
CLEAN_SEMANTIC_ORACLE_KINDS = {
    "bpftool_prog_run",
    "attach_or_runtime",
    "environment_config",
    "custom_oracle",
}
ALLOWED_EXCLUSION_REASONS = {
    "verifier_accepts",
    "unstable",
    "not_reproducible",
    "oracle_insufficient",
    "bpfix_unsupported",
    "duplicate_or_near_duplicate",
    "out_of_scope",
    "license_unclear",
}
REQUIRED_CLEAN_ADMISSION_FLAGS = {
    "model_result_used_for_admission": False,
    "case_ids_opaque_in_prompt": True,
    "result_blind_case_selection": True,
    "admitted_before_first_clean_run": True,
    "prompt_manifest_required": True,
}
CANDIDATE_ADMISSION_FLAGS = {
    "model_result_used_for_admission": False,
    "case_ids_opaque_in_prompt": True,
    "result_blind_case_selection": True,
}
CLEAN60_BUCKET_TARGETS = {
    "proof_lifecycle": 18,
    "source_object_correlation": 12,
    "modern_bpf_protocol": 15,
    "helper_memory_contract": 8,
    "environment_config_boundary": 7,
}
CLEAN60_MIN_SOURCE_CORRELATION_DIFFICULTY = 15
CLEAN60_MIN_MISLEADING_FINAL_LINE_PER_BUCKET = 3
C_NEAR_DUPLICATE_SHINGLE_SIZE = 7
C_NEAR_DUPLICATE_JACCARD_THRESHOLD = 0.82
C_NEAR_DUPLICATE_CONTAINMENT_THRESHOLD = 0.92
C_KEYWORDS_AND_STABLE_IDENTIFIERS = {
    "SEC",
    "__always_inline",
    "__builtin_memcpy",
    "__u8",
    "__u16",
    "__u32",
    "__u64",
    "bool",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "else",
    "enum",
    "for",
    "goto",
    "if",
    "int",
    "long",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
}
STABLE_IDENTIFIER_PREFIXES = (
    "BPF_",
    "ETH_",
    "IPPROTO_",
    "TC_",
    "XDP_",
    "bpf_",
)
MANIFEST_PROFILES = {
    "dev": "dev_calibration",
    "candidate": "candidate_staging",
    "clean60": "clean_heldout",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def infer_expected_count(path: Path) -> int | None:
    match = re.search(r"(\d+)", path.stem)
    return int(match.group(1)) if match else None


def duplicates(items: list[str]) -> list[str]:
    seen: set[str] = set()
    repeated: list[str] = []
    for item in items:
        if item in seen and item not in repeated:
            repeated.append(item)
        seen.add(item)
    return sorted(repeated)


def case_index(root: Path) -> dict[str, Path]:
    return {case.name: case for case in run_suite.discover_cases(root)}


def case_digest(case_dir: Path) -> str:
    digest = hashlib.sha256()
    for name in sorted(audit_cases.REQUIRED_FILES):
        path = case_dir / name
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def strip_c_comments_and_literals(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//.*", " ", text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', " STR ", text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", " CHR ", text)
    return text


def normalized_c_tokens(path: Path) -> list[str]:
    text = strip_c_comments_and_literals(path.read_text(encoding="utf-8", errors="replace"))
    tokens: list[str] = []
    token_re = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*"
        r"|0x[0-9a-fA-F]+"
        r"|\d+"
        r"|==|!=|<=|>=|->|&&|\|\||<<|>>"
        r"|[-+*/%&|^~!<>=?:;,.(){}\[\]]"
    )
    for line in text.splitlines():
        stripped = line.lstrip()
        if re.match(r"#\s*include\b", stripped):
            continue
        if stripped.startswith("#"):
            line = stripped[1:]
        for token in token_re.findall(line):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
                if token in C_KEYWORDS_AND_STABLE_IDENTIFIERS or token.startswith(STABLE_IDENTIFIER_PREFIXES):
                    tokens.append(token)
                else:
                    tokens.append("ID")
            elif re.fullmatch(r"0x[0-9a-fA-F]+|\d+", token):
                tokens.append("NUM")
            else:
                tokens.append(token)
    return tokens


def token_shingles(tokens: list[str], size: int = C_NEAR_DUPLICATE_SHINGLE_SIZE) -> set[tuple[str, ...]]:
    if len(tokens) < size:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[index : index + size]) for index in range(len(tokens) - size + 1)}


def c_source_shingles(path: Path) -> set[tuple[str, ...]]:
    return token_shingles(normalized_c_tokens(path))


def jaccard(left: set[tuple[str, ...]], right: set[tuple[str, ...]]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def containment(left: set[tuple[str, ...]], right: set[tuple[str, ...]]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / min(len(left), len(right))


def near_duplicate_scores(
    left: set[tuple[str, ...]],
    right: set[tuple[str, ...]],
) -> tuple[float, float]:
    return jaccard(left, right), containment(left, right)


def is_near_duplicate(jaccard_score: float, containment_score: float) -> bool:
    return (
        jaccard_score >= C_NEAR_DUPLICATE_JACCARD_THRESHOLD
        or containment_score >= C_NEAR_DUPLICATE_CONTAINMENT_THRESHOLD
    )


def bytes_digest(payload: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(payload)
    return digest.hexdigest()


def upstream_repo_basename(upstream_project: str) -> str:
    project = upstream_project.rstrip("/")
    basename = project.rsplit("/", 1)[-1]
    return basename.removesuffix(".git")


def project_url_parts(url: str) -> tuple[str, list[str]] | None:
    if url.startswith("git@"):
        try:
            host, path = url[4:].split(":", 1)
        except ValueError:
            return None
        host = host.lower()
        raw_parts = path.split("/")
    else:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        host = parsed.netloc.split("@")[-1].lower()
        raw_parts = parsed.path.strip("/").split("/")
    parts = [unquote(part) for part in raw_parts if part]
    if parts and parts[-1].endswith(".git"):
        parts[-1] = parts[-1][:-4]
    if not host or len(parts) < 2:
        return None
    return host, parts


def project_url_key(url: str) -> str | None:
    parts = project_url_parts(url)
    if parts is None:
        return None
    host, path_parts = parts
    return host + "/" + "/".join(part.lower() for part in path_parts)


def source_url_matches_provenance(
    source_url: str,
    *,
    upstream_project: str,
    upstream_ref: str,
    upstream_path: str,
) -> bool:
    parsed_source = urlparse(source_url)
    if parsed_source.query or parsed_source.fragment:
        return False
    source_parts = project_url_parts(source_url)
    upstream_parts = project_url_parts(upstream_project)
    if source_parts is None or upstream_parts is None:
        return False
    source_host, source_path = source_parts
    upstream_host, upstream_repo_path = upstream_parts
    if source_host != upstream_host:
        return False

    file_path = list(PurePosixPath(upstream_path).parts)
    accepted_paths = [
        upstream_repo_path + ["blob", upstream_ref] + file_path,
        upstream_repo_path + ["-", "blob", upstream_ref] + file_path,
    ]
    return source_path in accepted_paths


def upstream_root(root: Path) -> Path:
    return Path(os.environ.get("BPFIX_TEST_UPSTREAM_ROOT", root.parent)).resolve()


def is_usable_git_checkout(candidate: Path) -> bool:
    if not (candidate / ".git").exists():
        return False
    result = subprocess.run(
        ["git", "-C", str(candidate), "rev-parse", "--git-dir"],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def checkout_matches_upstream_remote(candidate: Path, upstream_project: str) -> bool:
    if not is_usable_git_checkout(candidate):
        return False
    remote_matches, _ = local_repo_matches_upstream_project(candidate, upstream_project)
    return remote_matches


def resolve_local_upstream_repo(root: Path, upstream_project: str) -> Path | None:
    base = upstream_repo_basename(upstream_project)
    if not base:
        return None
    search_root = upstream_root(root)
    if search_root.exists():
        lower_base = base.lower()
        direct = search_root / base
        if is_usable_git_checkout(direct):
            return direct
        for child in search_root.iterdir():
            if child.is_dir() and child.name.lower() == lower_base and is_usable_git_checkout(child):
                return child
        for parent in search_root.iterdir():
            if not parent.is_dir():
                continue
            candidate = parent / base
            if is_usable_git_checkout(candidate):
                return candidate
            for child in parent.iterdir():
                if child.is_dir() and child.name.lower() == lower_base and is_usable_git_checkout(child):
                    return child
        for child in search_root.iterdir():
            if child.is_dir() and checkout_matches_upstream_remote(child, upstream_project):
                return child
        for parent in search_root.iterdir():
            if not parent.is_dir():
                continue
            for child in parent.iterdir():
                if child.is_dir() and checkout_matches_upstream_remote(child, upstream_project):
                    return child
    return None


def git_bytes(repo: Path, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=False,
    )


def local_repo_matches_upstream_project(repo: Path, upstream_project: str) -> tuple[bool, list[str]]:
    expected = project_url_key(upstream_project)
    if expected is None:
        return False, []
    remote = git_bytes(repo, ["remote", "get-url", "--all", "origin"])
    urls = [
        line.strip()
        for line in remote.stdout.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    all_remotes = git_bytes(repo, ["remote", "-v"])
    urls.extend(
        line.split()[1]
        for line in all_remotes.stdout.decode("utf-8", errors="replace").splitlines()
        if len(line.split()) >= 2
    )
    urls = sorted(set(urls))
    return any(project_url_key(url) == expected for url in urls), urls


def safe_upstream_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value.strip()) and not path.is_absolute() and ".." not in path.parts


def spdx_license_from_source(payload: bytes) -> str | None:
    text = payload[:4096].decode("utf-8", errors="replace")
    for line in text.splitlines()[:20]:
        match = re.search(r"SPDX-License-Identifier:\s*(.+)$", line)
        if match:
            return match.group(1).strip().removesuffix("*/").strip()
    return None


def bpfix_bench_source_fingerprints(root: Path) -> dict[str, list[str]]:
    cases_root = root / "bpfix-bench" / "cases"
    fingerprints: dict[str, list[str]] = {}
    if not cases_root.exists():
        return fingerprints
    for source in sorted(cases_root.rglob("*.c")):
        digest = file_digest(source)
        fingerprints.setdefault(digest, []).append(str(source.relative_to(root)))
    return fingerprints


def bpfix_bench_source_paths(root: Path) -> list[Path]:
    cases_root = root / "bpfix-bench" / "cases"
    if not cases_root.exists():
        return []
    return sorted(cases_root.rglob("*.c"))


def case_fingerprints(case_ids: list[str], known_cases: dict[str, Path]) -> dict[str, dict[str, str]]:
    fingerprints: dict[str, dict[str, str]] = {}
    for case_id in case_ids:
        case_dir = known_cases.get(case_id)
        if case_dir is None:
            continue
        fingerprints[case_id] = {
            "case_sha256": case_digest(case_dir),
            "buggy_source_sha256": file_digest(case_dir / "buggy.bpf.c"),
        }
    return fingerprints


def source_path_label(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def case_source_paths(case_ids: list[str], known_cases: dict[str, Path]) -> dict[str, Path]:
    return {
        case_id: known_cases[case_id] / "buggy.bpf.c"
        for case_id in case_ids
        if case_id in known_cases and (known_cases[case_id] / "buggy.bpf.c").exists()
    }


def near_duplicate_source_matches(
    *,
    current_ids: list[str],
    known_cases: dict[str, Path],
    root: Path,
    other_case_ids: list[str] | None = None,
    other_sources: list[Path] | None = None,
    other_label: str,
) -> list[dict[str, Any]]:
    current_sources = case_source_paths(current_ids, known_cases)
    current_shingles = {
        case_id: c_source_shingles(source)
        for case_id, source in current_sources.items()
    }
    matches: list[dict[str, Any]] = []

    if other_case_ids is None and other_sources is None:
        items: list[tuple[str, Path, set[tuple[str, ...]]]] = [
            (case_id, current_sources[case_id], shingles)
            for case_id, shingles in current_shingles.items()
        ]
        for left_index, (left_case, left_source, left_shingles) in enumerate(items):
            for right_case, right_source, right_shingles in items[left_index + 1 :]:
                jaccard_score, containment_score = near_duplicate_scores(left_shingles, right_shingles)
                if is_near_duplicate(jaccard_score, containment_score):
                    matches.append(
                        {
                            "case": left_case,
                            "source": source_path_label(left_source, root),
                            "overlaps_case": right_case,
                            "overlaps_source": source_path_label(right_source, root),
                            "corpus": other_label,
                            "jaccard": round(jaccard_score, 4),
                            "containment": round(containment_score, 4),
                        }
                    )
        return matches

    compared: list[tuple[str, Path, set[tuple[str, ...]]]] = []
    if other_case_ids is not None:
        other_case_sources = case_source_paths(other_case_ids, known_cases)
        compared.extend(
            (
                case_id,
                source,
                c_source_shingles(source),
            )
            for case_id, source in other_case_sources.items()
        )
    if other_sources is not None:
        compared.extend(
            (
                source_path_label(source, root),
                source,
                c_source_shingles(source),
            )
            for source in other_sources
            if source.exists()
        )

    for case_id, source in current_sources.items():
        left_shingles = current_shingles[case_id]
        for other_id, other_source, right_shingles in compared:
            if source.resolve() == other_source.resolve():
                continue
            jaccard_score, containment_score = near_duplicate_scores(left_shingles, right_shingles)
            if is_near_duplicate(jaccard_score, containment_score):
                matches.append(
                    {
                        "case": case_id,
                        "source": source_path_label(source, root),
                        "overlaps_case": other_id,
                        "overlaps_source": source_path_label(other_source, root),
                        "corpus": other_label,
                        "jaccard": round(jaccard_score, 4),
                        "containment": round(containment_score, 4),
                    }
                )
    return sorted(
        matches,
        key=lambda match: (-match["containment"], -match["jaccard"], match["case"], match["overlaps_case"]),
    )


def manifest_case_fingerprints(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    manifest = read_manifest(path)
    defaults = manifest.get("case_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        return {}
    fingerprints: dict[str, dict[str, str]] = {}
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            continue
        case = {**defaults, **raw_case}
        case_id = case.get("case_id")
        if not isinstance(case_id, str):
            continue
        values: dict[str, str] = {}
        for key in ["case_sha256", "buggy_source_sha256"]:
            if isinstance(case.get(key), str):
                values[key] = case[key]
        if values:
            fingerprints[case_id] = values
    return fingerprints


def manifest_case_oracle_kinds(manifest: dict[str, Any]) -> dict[str, list[str]]:
    defaults = manifest.get("case_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        return {}
    values: dict[str, list[str]] = {}
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            continue
        case = {**defaults, **raw_case}
        case_id = case.get("case_id")
        oracle_kind = case.get("oracle_kind")
        if isinstance(case_id, str) and isinstance(oracle_kind, list):
            values[case_id] = [kind for kind in oracle_kind if isinstance(kind, str)]
    return values


def manifest_cases_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    defaults = manifest.get("case_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        return {}
    values: dict[str, dict[str, Any]] = {}
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            continue
        case = {**defaults, **raw_case}
        case_id = case.get("case_id")
        if isinstance(case_id, str):
            values[case_id] = case
    return values


def missing_manifest_fingerprints(path: Path, case_ids: list[str]) -> list[str]:
    if not path.exists():
        return []
    fingerprints = manifest_case_fingerprints(path)
    missing: list[str] = []
    for case_id in case_ids:
        values = fingerprints.get(case_id, {})
        if "case_sha256" not in values or "buggy_source_sha256" not in values:
            missing.append(case_id)
    return missing


def split_manifest_path(split: Path, root: Path) -> Path:
    splits_dir = root / "bpfix-test" / "splits"
    known = {
        (splits_dir / "dev40.txt").resolve(): splits_dir / "dev40.manifest.json",
        (splits_dir / "real-seed-candidates.txt").resolve(): splits_dir / "real-seed-candidates.manifest.json",
        (splits_dir / "clean60.txt").resolve(): splits_dir / "clean60.manifest.json",
    }
    return known.get(split.resolve(), split.with_suffix(".manifest.json"))


def overlapping_fingerprints(
    current_ids: list[str],
    other_ids: list[str],
    known_cases: dict[str, Path],
    *,
    other_manifest: Path | None = None,
) -> dict[str, list[dict[str, str]]]:
    current = case_fingerprints(current_ids, known_cases)
    other = case_fingerprints(other_ids, known_cases)
    if other_manifest is not None:
        for case_id, values in manifest_case_fingerprints(other_manifest).items():
            other.setdefault(case_id, {}).update(values)
    overlaps: dict[str, list[dict[str, str]]] = {
        "case_sha256": [],
        "buggy_source_sha256": [],
    }
    for fingerprint_name in overlaps:
        other_by_hash = {
            values[fingerprint_name]: case_id
            for case_id, values in other.items()
            if fingerprint_name in values
        }
        for case_id, values in current.items():
            digest = values.get(fingerprint_name)
            other_case = other_by_hash.get(digest)
            if digest and other_case:
                overlaps[fingerprint_name].append(
                    {
                        "case": case_id,
                        "overlaps_case": other_case,
                        "sha256": digest,
                    }
                )
    return {name: matches for name, matches in overlaps.items() if matches}


def format_near_duplicate_matches(matches: list[dict[str, Any]], *, limit: int = 5) -> str:
    formatted = []
    for match in matches[:limit]:
        formatted.append(
            f"{match['case']}~{match['overlaps_case']}@j={match['jaccard']:.4f}/c={match['containment']:.4f}"
        )
    suffix = "" if len(matches) <= limit else f", ... {len(matches) - limit} more"
    return ", ".join(formatted) + suffix


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{path}: manifest must be a JSON object")
    return payload


def require_bool(value: Any) -> bool:
    return isinstance(value, bool)


def require_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def local_prior_result_cases(root: Path) -> dict[str, list[str]]:
    prior_cases: dict[str, list[str]] = {}
    results_dir = root / "bpfix-test" / "results"
    if not results_dir.exists():
        return prior_cases
    for summary_path in sorted(results_dir.glob("**/summary.json")):
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        results = payload.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            case_id = result.get("case")
            if isinstance(case_id, str) and case_id:
                prior_cases.setdefault(case_id, []).append(str(summary_path.relative_to(root)))
    return prior_cases


def audit_selection_protocol(
    *,
    manifest: dict[str, Any],
    errors: list[str],
    label: str,
) -> dict[str, Any]:
    protocol = manifest.get("selection_protocol")
    if not isinstance(protocol, dict):
        errors.append(f"{label} selection_protocol must be an object")
        protocol = {}
    required_strings = [
        "case_source_policy",
        "admission_order_policy",
        "review_policy",
        "model_result_blinding_policy",
        "near_duplicate_policy",
    ]
    for field in required_strings:
        if not require_nonempty_string(protocol.get(field)):
            errors.append(f"{label} selection_protocol.{field} must be a non-empty string")
    return protocol


def audit_exclusion_ledger(
    *,
    manifest: dict[str, Any],
    errors: list[str],
    label: str,
) -> dict[str, Any]:
    ledger = manifest.get("seed_exclusion_ledger")
    if not isinstance(ledger, list):
        errors.append(f"{label} seed_exclusion_ledger must be a list")
        ledger = []
    reason_counts = {reason: 0 for reason in ALLOWED_EXCLUSION_REASONS}
    for index, row in enumerate(ledger):
        if not isinstance(row, dict):
            errors.append(f"seed_exclusion_ledger[{index}] must be an object")
            continue
        seed = row.get("seed")
        reason = row.get("reason")
        notes = row.get("notes")
        if not require_nonempty_string(seed):
            errors.append(f"seed_exclusion_ledger[{index}].seed must be a non-empty string")
        if reason not in ALLOWED_EXCLUSION_REASONS:
            errors.append(f"seed_exclusion_ledger[{index}].reason has invalid value {reason!r}")
        else:
            reason_counts[reason] += 1
        if not require_nonempty_string(notes):
            errors.append(f"seed_exclusion_ledger[{index}].notes must be a non-empty string")
        if row.get("model_result_used") is not False:
            errors.append(f"seed_exclusion_ledger[{index}].model_result_used must be false")
    return {
        "entries": len(ledger),
        "reason_counts": reason_counts,
    }


def audit_candidate_seed_ledger(
    *,
    manifest: dict[str, Any],
    case_ids: list[str],
    errors: list[str],
    label: str,
) -> dict[str, Any]:
    ledger = manifest.get("candidate_seed_ledger")
    if not isinstance(ledger, list):
        errors.append(f"{label} candidate_seed_ledger must be a list")
        ledger = []

    admitted_by_case: dict[str, int] = {}
    excluded_count = 0
    for index, row in enumerate(ledger):
        if not isinstance(row, dict):
            errors.append(f"candidate_seed_ledger[{index}] must be an object")
            continue
        decision = row.get("decision")
        seed = row.get("seed")
        notes = row.get("notes")
        if not require_nonempty_string(seed):
            errors.append(f"candidate_seed_ledger[{index}].seed must be a non-empty string")
        if decision not in {"admitted", "excluded"}:
            errors.append(f"candidate_seed_ledger[{index}].decision must be 'admitted' or 'excluded'")
        if row.get("decision_made_before_model_eval") is not True:
            errors.append(f"candidate_seed_ledger[{index}].decision_made_before_model_eval must be true")
        if row.get("model_result_used") is not False:
            errors.append(f"candidate_seed_ledger[{index}].model_result_used must be false")
        if not require_nonempty_string(notes):
            errors.append(f"candidate_seed_ledger[{index}].notes must be a non-empty string")

        if decision == "admitted":
            case_id = row.get("case_id")
            if not isinstance(case_id, str):
                errors.append(f"candidate_seed_ledger[{index}].case_id must be a string for admitted seeds")
            elif case_id not in case_ids:
                errors.append(f"candidate_seed_ledger[{index}].case_id {case_id!r} is not in split")
            else:
                admitted_by_case[case_id] = admitted_by_case.get(case_id, 0) + 1
        elif decision == "excluded":
            excluded_count += 1
            reason = row.get("reason")
            if reason not in ALLOWED_EXCLUSION_REASONS:
                errors.append(f"candidate_seed_ledger[{index}].reason has invalid value {reason!r}")

    for case_id in case_ids:
        count = admitted_by_case.get(case_id, 0)
        if count == 0:
            errors.append(f"{case_id}: {label} candidate_seed_ledger missing admitted row")
        elif count > 1:
            errors.append(f"{case_id}: {label} candidate_seed_ledger has duplicate admitted rows")

    return {
        "entries": len(ledger),
        "admitted": sum(1 for row in ledger if isinstance(row, dict) and row.get("decision") == "admitted"),
        "excluded": excluded_count,
    }


def audit_real_project_upstream(
    *,
    root: Path,
    case_id: str,
    provenance: dict[str, Any],
    errors: list[str],
    label: str,
) -> dict[str, Any]:
    error_count = len(errors)
    report: dict[str, Any] = {
        "verified": False,
        "repo": None,
        "remote_urls": [],
        "source_sha256": None,
        "spdx_license": None,
    }
    upstream_project = provenance.get("upstream_project")
    upstream_ref = provenance.get("upstream_ref")
    upstream_path = provenance.get("upstream_path")
    upstream_license = provenance.get("upstream_license")
    upstream_file_sha256 = provenance.get("upstream_file_sha256")
    source_url = provenance.get("source")

    if not isinstance(upstream_ref, str) or not re.fullmatch(r"[0-9a-f]{40}", upstream_ref):
        errors.append(f"{case_id}: {label} real_project_seed provenance.upstream_ref must be a pinned 40-hex commit")
    if not isinstance(upstream_path, str) or not safe_upstream_path(upstream_path):
        errors.append(f"{case_id}: {label} real_project_seed provenance.upstream_path must be a safe relative path")
        return report
    if not isinstance(upstream_file_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", upstream_file_sha256):
        errors.append(f"{case_id}: {label} real_project_seed provenance.upstream_file_sha256 must be a 64-hex sha256")
        return report
    if not isinstance(upstream_project, str) or not upstream_project.strip():
        return report
    if isinstance(source_url, str) and isinstance(upstream_ref, str) and isinstance(upstream_path, str):
        if not source_url_matches_provenance(
            source_url,
            upstream_project=upstream_project,
            upstream_ref=upstream_ref,
            upstream_path=upstream_path,
        ):
            errors.append(
                f"{case_id}: {label} provenance.source must be the canonical upstream blob URL"
            )

    repo = resolve_local_upstream_repo(root, upstream_project)
    if repo is None:
        errors.append(
            f"{case_id}: {label} upstream repo {upstream_project!r} not found under {upstream_root(root)}; "
            "set BPFIX_TEST_UPSTREAM_ROOT for paper-grade provenance checks"
        )
        return report
    report["repo"] = str(repo)
    remote_matches, remote_urls = local_repo_matches_upstream_project(repo, upstream_project)
    report["remote_urls"] = remote_urls
    if not remote_matches:
        errors.append(
            f"{case_id}: {label} local upstream repo remote does not match provenance.upstream_project"
        )

    commit_check = git_bytes(repo, ["cat-file", "-e", f"{upstream_ref}^{{commit}}"])
    if commit_check.returncode != 0:
        errors.append(f"{case_id}: {label} upstream_ref {upstream_ref} is not a commit in {repo}")
        return report

    source = git_bytes(repo, ["show", f"{upstream_ref}:{upstream_path}"])
    if source.returncode != 0:
        errors.append(f"{case_id}: {label} upstream_path {upstream_path!r} not found at {upstream_ref} in {repo}")
        return report

    computed_sha = bytes_digest(source.stdout)
    report["source_sha256"] = computed_sha
    if computed_sha != upstream_file_sha256:
        errors.append(
            f"{case_id}: {label} upstream_file_sha256 mismatch: recorded {upstream_file_sha256}, computed {computed_sha}"
        )

    spdx = spdx_license_from_source(source.stdout)
    report["spdx_license"] = spdx
    if spdx is None:
        errors.append(f"{case_id}: {label} upstream source is missing an SPDX-License-Identifier header")
    elif spdx != upstream_license:
        errors.append(f"{case_id}: {label} upstream_license {upstream_license!r} does not match SPDX {spdx!r}")

    if provenance.get("license") != upstream_license:
        errors.append(f"{case_id}: {label} provenance.license must match upstream_license for real_project_seed")

    report["verified"] = len(errors) == error_count
    return report


def audit_case_review_contract(
    case_id: str,
    case: dict[str, Any],
    errors: list[str],
    *,
    root: Path,
    label: str,
) -> dict[str, Any]:
    source_category = case.get("source_category")
    review = case.get("review")
    if not isinstance(review, dict):
        errors.append(f"{case_id}: {label} review must be an object")
        review = {}
    for field in ["reviewer", "reviewed_at", "bug_summary", "oracle_rationale", "provenance_rationale"]:
        if not require_nonempty_string(review.get(field)):
            errors.append(f"{case_id}: {label} review.{field} must be a non-empty string")
    if review.get("bug_confirmed") is not True:
        errors.append(f"{case_id}: {label} review.bug_confirmed must be true")
    if review.get("oracle_adequate") is not True:
        errors.append(f"{case_id}: {label} review.oracle_adequate must be true")
    if review.get("not_seen_in_prior_eval") is not True:
        errors.append(f"{case_id}: {label} review.not_seen_in_prior_eval must be true")

    provenance = case.get("provenance")
    if not isinstance(provenance, dict):
        errors.append(f"{case_id}: {label} provenance must be an object")
        provenance = {}
    for field in ["seed_type", "source", "license", "minimization"]:
        if not require_nonempty_string(provenance.get(field)):
            errors.append(f"{case_id}: {label} provenance.{field} must be a non-empty string")
    if source_category == "real_project_seed":
        for field in ["upstream_project", "upstream_ref", "upstream_path", "upstream_license", "upstream_file_sha256"]:
            if not require_nonempty_string(provenance.get(field)):
                errors.append(f"{case_id}: {label} real_project_seed provenance.{field} must be a non-empty string")
        upstream_report = audit_real_project_upstream(
            root=root,
            case_id=case_id,
            provenance=provenance,
            errors=errors,
            label=label,
        )
    else:
        upstream_report = None
    if provenance.get("derived_from_dev40") is not False:
        errors.append(f"{case_id}: {label} provenance.derived_from_dev40 must be false")
    if provenance.get("model_result_used") is not False:
        errors.append(f"{case_id}: {label} provenance.model_result_used must be false")

    oracle_obligation = case.get("oracle_obligation")
    if not isinstance(oracle_obligation, dict):
        errors.append(f"{case_id}: {label} oracle_obligation must be an object")
        oracle_obligation = {}
    for field in ["functional_semantics", "verifier_reject_reason", "success_criteria"]:
        values = oracle_obligation.get(field)
        if not isinstance(values, list) or not values or any(not require_nonempty_string(value) for value in values):
            errors.append(f"{case_id}: {label} oracle_obligation.{field} must be a non-empty string list")

    return {
        "reviewer": review.get("reviewer"),
        "reviewed_at": review.get("reviewed_at"),
        "source": provenance.get("source"),
        "seed_type": provenance.get("seed_type"),
        "upstream": upstream_report,
    }


def audit_manifest(
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    expected_split_id: str,
    case_ids: list[str],
    known_cases: dict[str, Path],
    profile: str,
) -> tuple[dict[str, Any], list[str]]:
    root = repo_root()
    errors: list[str] = []
    warnings: list[str] = []
    defaults = manifest.get("case_defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}
        errors.append("manifest.case_defaults must be an object when present")

    cases = manifest.get("cases")
    if not isinstance(cases, list):
        cases = []
        errors.append("manifest.cases must be a list")

    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"manifest.schema_version must be {SCHEMA_VERSION!r}")
    expected_profile = MANIFEST_PROFILES[profile]
    if manifest.get("profile") != expected_profile:
        errors.append(f"manifest.profile must be {expected_profile!r}")
    if manifest.get("split_id") != expected_split_id:
        errors.append(f"manifest.split_id must be {expected_split_id!r}")

    manifest_ids = [case.get("case_id") for case in cases if isinstance(case, dict)]
    if manifest_ids != case_ids:
        errors.append("manifest case order must exactly match the split file")
    for duplicate in duplicates([case_id for case_id in manifest_ids if isinstance(case_id, str)]):
        errors.append(f"duplicate manifest case id: {duplicate}")

    admission_policy = manifest.get("admission_policy")
    if not isinstance(admission_policy, dict):
        admission_policy = {}
        errors.append("manifest.admission_policy must be an object")
    freeze = manifest.get("freeze")
    if not isinstance(freeze, dict):
        freeze = {}
        errors.append("manifest.freeze must be an object")

    selection_protocol: dict[str, Any] = {}
    exclusion_summary: dict[str, Any] = {"entries": 0, "reason_counts": {}}
    candidate_seed_summary: dict[str, Any] = {"entries": 0, "admitted": 0, "excluded": 0}
    if profile == "candidate":
        for key, expected in CANDIDATE_ADMISSION_FLAGS.items():
            if admission_policy.get(key) is not expected:
                errors.append(f"candidate admission_policy.{key} must be {str(expected).lower()}")
        if freeze.get("frozen") is not False:
            errors.append("candidate freeze.frozen must be false until promotion to clean60")
        selection_protocol = audit_selection_protocol(manifest=manifest, errors=errors, label="candidate")
        exclusion_summary = audit_exclusion_ledger(manifest=manifest, errors=errors, label="candidate")
        candidate_seed_summary = audit_candidate_seed_ledger(
            manifest=manifest,
            case_ids=case_ids,
            errors=errors,
            label="candidate",
        )
    elif profile == "clean60":
        for key, expected in REQUIRED_CLEAN_ADMISSION_FLAGS.items():
            if admission_policy.get(key) is not expected:
                errors.append(f"clean60 admission_policy.{key} must be {str(expected).lower()}")
        if freeze.get("frozen") is not True:
            errors.append("clean60 freeze.frozen must be true before benchmark runs")
        if freeze.get("fingerprints_frozen") is not True:
            errors.append("clean60 freeze.fingerprints_frozen must be true before benchmark runs")
        selection_protocol = audit_selection_protocol(manifest=manifest, errors=errors, label="clean60")
        exclusion_summary = audit_exclusion_ledger(manifest=manifest, errors=errors, label="clean60")
        candidate_seed_summary = audit_candidate_seed_ledger(
            manifest=manifest,
            case_ids=case_ids,
            errors=errors,
            label="clean60",
        )

    bucket_counts = {bucket: 0 for bucket in BUCKETS}
    source_counts = {category: 0 for category in SOURCE_CATEGORIES}
    prog_type_counts: dict[str, int] = {}
    helper_or_state_count = 0
    realish_count = 0
    source_correlation_difficulty_count = 0
    misleading_final_line_counts = {bucket: 0 for bucket in BUCKETS}
    hash_mismatches: list[str] = []
    per_case_reports: list[dict[str, Any]] = []
    clean_buggy_source_hashes: dict[str, str] = {}

    for index, raw_case in enumerate(cases):
        if not isinstance(raw_case, dict):
            errors.append(f"manifest.cases[{index}] must be an object")
            continue
        case = {**defaults, **raw_case}
        case_id = case.get("case_id")
        if not isinstance(case_id, str):
            errors.append(f"manifest.cases[{index}].case_id must be a string")
            continue

        missing_fields = [
            field
            for field in [
                "bucket",
                "source_category",
                "prog_type",
                "origin",
                "review_status",
                "oracle_kind",
                "requires_helper_or_state",
                "uses_success_predicate",
            ]
            if field not in case
        ]
        if missing_fields:
            errors.append(f"{case_id}: manifest missing fields: {', '.join(missing_fields)}")

        bucket = case.get("bucket")
        source_category = case.get("source_category")
        prog_type = case.get("prog_type")
        oracle_kind = case.get("oracle_kind")
        if bucket not in BUCKETS:
            errors.append(f"{case_id}: invalid bucket {bucket!r}")
        else:
            bucket_counts[bucket] += 1
        if source_category not in SOURCE_CATEGORIES:
            errors.append(f"{case_id}: invalid source_category {source_category!r}")
        else:
            source_counts[source_category] += 1
            if source_category == "real_project_seed":
                realish_count += 1
            if (
                profile == "candidate"
                and expected_split_id == "real-seed-candidates"
                and source_category != "real_project_seed"
            ):
                errors.append(f"{case_id}: real-seed-candidates requires source_category real_project_seed")
        if prog_type not in PROG_TYPES:
            errors.append(f"{case_id}: invalid prog_type {prog_type!r}")
        else:
            prog_type_counts[prog_type] = prog_type_counts.get(prog_type, 0) + 1
        if not isinstance(oracle_kind, list) or not oracle_kind:
            errors.append(f"{case_id}: oracle_kind must be a non-empty list")
        elif any(kind not in ORACLE_KINDS for kind in oracle_kind):
            errors.append(f"{case_id}: invalid oracle_kind entry")
        elif profile in {"candidate", "clean60"}:
            label = "candidate" if profile == "candidate" else "clean60"
            oracle_kind_set = set(oracle_kind)
            missing_oracles = sorted(BASE_CLEAN_ORACLE_KINDS - oracle_kind_set)
            if missing_oracles:
                errors.append(f"{case_id}: {label} oracle_kind missing: {', '.join(missing_oracles)}")
            if not CLEAN_SEMANTIC_ORACLE_KINDS & oracle_kind_set:
                errors.append(
                    f"{case_id}: {label} oracle_kind requires one semantic oracle: "
                    + ", ".join(sorted(CLEAN_SEMANTIC_ORACLE_KINDS))
                )
            if case.get("uses_success_predicate") is True and "proof_predicate" not in oracle_kind_set:
                errors.append(f"{case_id}: {label} uses_success_predicate requires oracle_kind proof_predicate")
            if (
                case.get("requires_helper_or_state") is True
                and not {"helper_state", "proof_predicate"} & oracle_kind_set
            ):
                errors.append(
                    f"{case_id}: {label} requires_helper_or_state requires oracle_kind helper_state or proof_predicate"
                )
        for bool_field in ["requires_helper_or_state", "uses_success_predicate"]:
            if not require_bool(case.get(bool_field)):
                errors.append(f"{case_id}: {bool_field} must be boolean")
        if case.get("requires_helper_or_state") is True:
            helper_or_state_count += 1
        if profile == "clean60":
            challenge_flags = case.get("challenge_flags")
            if not isinstance(challenge_flags, dict):
                errors.append(f"{case_id}: clean60 challenge_flags must be an object")
                challenge_flags = {}
            for flag in ["source_correlation_difficulty", "misleading_final_line", "semantic_duplicate_reviewed"]:
                if not require_bool(challenge_flags.get(flag)):
                    errors.append(f"{case_id}: clean60 challenge_flags.{flag} must be boolean")
            if challenge_flags.get("semantic_duplicate_reviewed") is not True:
                errors.append(f"{case_id}: clean60 challenge_flags.semantic_duplicate_reviewed must be true")
            if challenge_flags.get("source_correlation_difficulty") is True:
                source_correlation_difficulty_count += 1
            if challenge_flags.get("misleading_final_line") is True and bucket in misleading_final_line_counts:
                misleading_final_line_counts[bucket] += 1

        computed_hash = None
        computed_buggy_source_hash = None
        if case_id in known_cases:
            case_dir = known_cases[case_id]
            computed_hash = case_digest(case_dir)
            computed_buggy_source_hash = file_digest(case_dir / "buggy.bpf.c")
        recorded_hash = case.get("case_sha256")
        recorded_buggy_source_hash = case.get("buggy_source_sha256")
        if profile in {"candidate", "clean60"}:
            label = "candidate" if profile == "candidate" else "clean60"
            review_report = audit_case_review_contract(case_id, case, errors, root=root, label=label)
            if not require_nonempty_string(case.get("origin")):
                errors.append(f"{case_id}: {label} origin must be a non-empty string")
            allowed_review_statuses = (
                {"candidate_reviewed", "independent_reviewed"}
                if profile == "candidate"
                else {"independent_reviewed"}
            )
            if case.get("review_status") not in allowed_review_statuses:
                expected_status = "candidate_reviewed or independent_reviewed" if profile == "candidate" else "independent_reviewed"
                errors.append(f"{case_id}: {label} review_status must be {expected_status}")
            reviewer = review_report.get("reviewer")
            if profile == "clean60" and isinstance(reviewer, str) and "required before paper use" in reviewer.lower():
                errors.append(f"{case_id}: clean60 review_status contradicts review.reviewer")
            if source_category == "dev_calibration":
                errors.append(f"{case_id}: {label} case cannot use dev_calibration source_category")
            if not isinstance(recorded_hash, str):
                errors.append(f"{case_id}: {label} case_sha256 is required")
            elif computed_hash is not None and recorded_hash != computed_hash:
                errors.append(f"{case_id}: case_sha256 does not match current case files")
                hash_mismatches.append(case_id)
            if not isinstance(recorded_buggy_source_hash, str):
                errors.append(f"{case_id}: {label} buggy_source_sha256 is required")
            elif (
                computed_buggy_source_hash is not None
                and recorded_buggy_source_hash != computed_buggy_source_hash
            ):
                errors.append(f"{case_id}: buggy_source_sha256 does not match current buggy.bpf.c")
                hash_mismatches.append(case_id)
            if isinstance(recorded_buggy_source_hash, str):
                previous = clean_buggy_source_hashes.get(recorded_buggy_source_hash)
                if previous is not None:
                    errors.append(
                        f"{case_id}: {label} buggy_source_sha256 duplicates {previous}"
                    )
                else:
                    clean_buggy_source_hashes[recorded_buggy_source_hash] = case_id
        elif recorded_hash is not None and computed_hash is not None and recorded_hash != computed_hash:
            if freeze.get("fingerprints_frozen") is True:
                errors.append(f"{case_id}: case_sha256 does not match frozen manifest fingerprint")
            else:
                warnings.append(f"{case_id}: case_sha256 does not match current case files")
            hash_mismatches.append(case_id)
        if profile != "clean60" and freeze.get("fingerprints_frozen") is True:
            if not isinstance(recorded_hash, str):
                errors.append(f"{case_id}: frozen manifest requires case_sha256")
            if not isinstance(recorded_buggy_source_hash, str):
                errors.append(f"{case_id}: frozen manifest requires buggy_source_sha256")
            elif (
                computed_buggy_source_hash is not None
                and recorded_buggy_source_hash != computed_buggy_source_hash
            ):
                errors.append(f"{case_id}: buggy_source_sha256 does not match frozen manifest fingerprint")
                hash_mismatches.append(case_id)

        per_case_reports.append(
            {
                "case": case_id,
                "bucket": bucket,
                "source_category": source_category,
                "prog_type": prog_type,
                "computed_case_sha256": computed_hash,
                "recorded_case_sha256": recorded_hash,
                "computed_buggy_source_sha256": computed_buggy_source_hash,
                "recorded_buggy_source_sha256": recorded_buggy_source_hash,
                **({"review": review_report} if profile in {"candidate", "clean60"} else {}),
            }
        )

    if profile == "clean60":
        for bucket, target in CLEAN60_BUCKET_TARGETS.items():
            if bucket_counts.get(bucket, 0) != target:
                errors.append(f"clean60 bucket {bucket} must have exactly {target} cases")
        if prog_type_counts.get("xdp", 0) > 25:
            errors.append("clean60 xdp prog_type count must be <= 25")
        if realish_count != len(case_ids):
            errors.append("clean60 must use real_project_seed provenance for every case")
        if helper_or_state_count < 20:
            errors.append("clean60 must include at least 20 helper/state-obligation cases")
        if source_correlation_difficulty_count < CLEAN60_MIN_SOURCE_CORRELATION_DIFFICULTY:
            errors.append(
                "clean60 must include at least "
                f"{CLEAN60_MIN_SOURCE_CORRELATION_DIFFICULTY} source-correlation difficulty cases"
            )
        for bucket in sorted(BUCKETS):
            count = misleading_final_line_counts.get(bucket, 0)
            if count < CLEAN60_MIN_MISLEADING_FINAL_LINE_PER_BUCKET:
                errors.append(
                    f"clean60 bucket {bucket} must include at least "
                    f"{CLEAN60_MIN_MISLEADING_FINAL_LINE_PER_BUCKET} misleading-final-line cases"
                )

    return (
        {
            "enabled": True,
            "path": str(manifest_path),
            "profile": profile,
            "case_count": len(cases),
            "bucket_counts": bucket_counts,
            "source_counts": source_counts,
            "prog_type_counts": prog_type_counts,
            "helper_or_state_count": helper_or_state_count,
            "realish_count": realish_count,
            "source_correlation_difficulty_count": source_correlation_difficulty_count,
            "misleading_final_line_counts": misleading_final_line_counts,
            "hash_mismatches": hash_mismatches,
            "selection_protocol": selection_protocol,
            "candidate_seed_ledger": candidate_seed_summary,
            "seed_exclusion_ledger": exclusion_summary,
            "warnings": warnings,
            "reports": per_case_reports,
        },
        errors,
    )


def positive_count(value: Any) -> bool:
    return isinstance(value, int) and value > 0


def audit_manifest_oracle_alignment(
    *,
    manifest: dict[str, Any],
    case_reports: list[dict[str, Any]],
    errors: list[str],
    label: str,
) -> None:
    manifest_cases = manifest_cases_by_id(manifest)
    reports_by_case = {
        report.get("case"): report
        for report in case_reports
        if isinstance(report.get("case"), str)
    }
    for case_id, case in manifest_cases.items():
        report = reports_by_case.get(case_id)
        if report is None:
            errors.append(f"{case_id}: {label} oracle alignment requires a case audit report")
            continue
        test = report.get("test")
        if not isinstance(test, dict):
            errors.append(f"{case_id}: {label} oracle alignment requires parseable test.py summary")
            continue

        oracle_kind = case.get("oracle_kind")
        oracle_kind_set = set(oracle_kind) if isinstance(oracle_kind, list) else set()
        uses_success_predicate = case.get("uses_success_predicate")
        requires_helper_or_state = case.get("requires_helper_or_state")
        success_predicates = test.get("required_success_predicates")
        success_substrings = test.get("required_success_substrings")
        functional_tests = test.get("functional_tests")
        has_success_predicate = positive_count(success_predicates)
        has_success_substring = positive_count(success_substrings)
        has_functional_tests = positive_count(functional_tests)
        has_custom_oracle = test.get("custom_oracle") is True

        if "bpftool_prog_run" in oracle_kind_set and not has_functional_tests:
            errors.append(f"{case_id}: {label} oracle_kind bpftool_prog_run requires functional_tests in test.py")
        if "proof_predicate" in oracle_kind_set and not has_success_predicate:
            errors.append(
                f"{case_id}: {label} oracle_kind proof_predicate requires required_success_predicates in test.py"
            )
        if uses_success_predicate is True and not has_success_predicate:
            errors.append(f"{case_id}: {label} uses_success_predicate requires required_success_predicates")
        if uses_success_predicate is False and has_success_predicate:
            errors.append(f"{case_id}: {label} test.py has success predicates but manifest uses_success_predicate is false")
        if has_success_predicate and "proof_predicate" not in oracle_kind_set:
            errors.append(f"{case_id}: {label} success predicates require oracle_kind proof_predicate")
        if requires_helper_or_state is True and not (has_success_predicate or has_success_substring):
            errors.append(
                f"{case_id}: {label} requires_helper_or_state needs required_success_substrings or predicates"
            )
        if "helper_state" in oracle_kind_set and not (has_success_predicate or has_success_substring):
            errors.append(f"{case_id}: {label} oracle_kind helper_state needs success substring or predicate checks")
        if "custom_oracle" in oracle_kind_set and not has_custom_oracle:
            errors.append(f"{case_id}: {label} oracle_kind custom_oracle requires custom_oracle test summary")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", type=Path, required=True, help="Split file containing case ids.")
    parser.add_argument("--expected-count", type=int, help="Required number of cases.")
    parser.add_argument("--manifest", type=Path, help="Machine-readable split manifest.")
    parser.add_argument(
        "--profile",
        choices=["dev", "candidate", "clean60"],
        help="Manifest policy profile to enforce. Defaults to clean60 for clean60 split names, candidate for real-seed-candidates, dev otherwise.",
    )
    parser.add_argument(
        "--disallow-overlap",
        type=Path,
        action="append",
        default=[],
        help="Reject case ids that also appear in this split.",
    )
    parser.add_argument("--audit-cases", action="store_true", help="Run structural case audit for split cases.")
    parser.add_argument("--smoke", action="store_true", help="Also run buggy-reject smoke for each split case.")
    return parser.parse_args(argv)


def audit_split(args: argparse.Namespace) -> dict[str, Any]:
    root = repo_root()
    case_ids = run_suite.read_split_file(args.split)
    expected_count = args.expected_count
    if expected_count is None:
        expected_count = infer_expected_count(args.split)
    profile_errors: list[str] = []
    split_implies_clean = "clean60" in args.split.stem
    split_implies_candidate = args.split.stem == "real-seed-candidates"
    if split_implies_clean:
        profile = "clean60"
        if args.profile in {"dev", "candidate"}:
            profile_errors.append(f"clean60 split cannot use --profile {args.profile}")
    elif split_implies_candidate:
        profile = args.profile or "candidate"
        if args.profile in {"dev", "clean60"}:
            profile_errors.append(f"real-seed-candidates split cannot use --profile {args.profile}")
    else:
        profile = args.profile or "dev"
    split_implies_dev40 = args.split.resolve() == (root / "bpfix-test" / "splits" / "dev40.txt").resolve()

    known_cases = case_index(root)
    bpfix_bench_sources = bpfix_bench_source_fingerprints(root) if profile in {"candidate", "clean60"} else {}
    split_duplicates = duplicates(case_ids)
    missing_cases = sorted(set(case_ids) - set(known_cases))
    overlap: dict[str, dict[str, Any]] = {}
    near_duplicates: dict[str, list[dict[str, Any]]] = {}
    disallow_overlap_paths = list(args.disallow_overlap)
    if profile in {"candidate", "clean60"}:
        dev40_split = root / "bpfix-test" / "splits" / "dev40.txt"
        explicit_paths = {path.resolve() for path in disallow_overlap_paths}
        if args.split.resolve() != dev40_split.resolve() and dev40_split.resolve() not in explicit_paths:
            disallow_overlap_paths.append(dev40_split)

    for other_split in disallow_overlap_paths:
        other_case_ids = run_suite.read_split_file(other_split)
        shared = sorted(set(case_ids) & set(other_case_ids))
        other_manifest = split_manifest_path(other_split, root)
        content_shared = overlapping_fingerprints(
            case_ids,
            other_case_ids,
            known_cases,
            other_manifest=other_manifest,
        )
        overlap[str(other_split)] = {
            "case_ids": shared,
            "manifest": str(other_manifest) if other_manifest.exists() else None,
            "content": content_shared,
        }

    errors: list[str] = []
    errors.extend(profile_errors)
    prior_eval_overlap: dict[str, list[str]] = {}
    if profile == "clean60":
        local_prior_cases = local_prior_result_cases(root)
        prior_eval_overlap = {
            case_id: local_prior_cases[case_id]
            for case_id in sorted(set(case_ids) & set(local_prior_cases))
        }
        if prior_eval_overlap:
            formatted = ", ".join(
                f"{case_id}~{paths[0]}" for case_id, paths in prior_eval_overlap.items()
            )
            errors.append(f"clean60 case appears in local prior LLM results: {formatted}")
    if expected_count is not None and len(case_ids) != expected_count:
        errors.append(f"expected {expected_count} cases, found {len(case_ids)}")
    if split_duplicates:
        errors.append(f"duplicate case ids: {', '.join(split_duplicates)}")
    if missing_cases:
        errors.append(f"unknown case ids: {', '.join(missing_cases)}")
    bpfix_bench_overlap: list[dict[str, Any]] = []
    if bpfix_bench_sources:
        for case_id in case_ids:
            case_dir = known_cases.get(case_id)
            if case_dir is None:
                continue
            digest = file_digest(case_dir / "buggy.bpf.c")
            matches = bpfix_bench_sources.get(digest)
            if matches:
                bpfix_bench_overlap.append(
                    {
                        "case": case_id,
                        "buggy_source_sha256": digest,
                        "bpfix_bench_sources": matches,
                    }
                )
        if bpfix_bench_overlap:
            formatted = ", ".join(
                f"{match['case']}~{match['bpfix_bench_sources'][0]}" for match in bpfix_bench_overlap
            )
            errors.append(f"buggy.bpf.c content overlap with bpfix-bench: {formatted}")
    if profile in {"candidate", "clean60"} and not missing_cases and not split_duplicates:
        within_matches = near_duplicate_source_matches(
            current_ids=case_ids,
            known_cases=known_cases,
            root=root,
            other_label="current split",
        )
        if within_matches:
            near_duplicates["current_split"] = within_matches
            errors.append(
                "near-duplicate buggy.bpf.c sources within split: "
                + format_near_duplicate_matches(within_matches)
            )

        dev40_split = root / "bpfix-test" / "splits" / "dev40.txt"
        if args.split.resolve() != dev40_split.resolve():
            dev40_matches = near_duplicate_source_matches(
                current_ids=case_ids,
                known_cases=known_cases,
                root=root,
                other_case_ids=run_suite.read_split_file(dev40_split),
                other_label="dev40",
            )
            if dev40_matches:
                near_duplicates["dev40"] = dev40_matches
                errors.append(
                    "near-duplicate buggy.bpf.c sources with dev40: "
                    + format_near_duplicate_matches(dev40_matches)
                )

        bench_matches = near_duplicate_source_matches(
            current_ids=case_ids,
            known_cases=known_cases,
            root=root,
            other_sources=bpfix_bench_source_paths(root),
            other_label="bpfix-bench",
        )
        if bench_matches:
            near_duplicates["bpfix_bench"] = bench_matches
            errors.append(
                "near-duplicate buggy.bpf.c sources with bpfix-bench: "
                + format_near_duplicate_matches(bench_matches)
            )
    for other_split, overlap_report in overlap.items():
        shared = overlap_report["case_ids"]
        if shared:
            errors.append(f"overlap with {other_split}: {', '.join(shared)}")
        for fingerprint_name, matches in overlap_report["content"].items():
            if matches:
                formatted = ", ".join(
                    f"{match['case']}~{match['overlaps_case']}" for match in matches
                )
                errors.append(f"{fingerprint_name} content overlap with {other_split}: {formatted}")
        manifest_path = overlap_report.get("manifest")
        if manifest_path:
            missing_fingerprints = missing_manifest_fingerprints(Path(manifest_path), run_suite.read_split_file(Path(other_split)))
            if missing_fingerprints:
                errors.append(
                    f"overlap manifest {manifest_path} missing frozen fingerprints for: "
                    + ", ".join(missing_fingerprints)
                )

    manifest_summary: dict[str, Any] = {"enabled": False}
    manifest_payload: dict[str, Any] | None = None
    manifest_oracle_kinds: dict[str, list[str]] = {}
    if split_implies_dev40 and args.manifest is None:
        errors.append("dev40 split requires --manifest")
    if profile in {"candidate", "clean60"} and args.manifest is None:
        errors.append(f"{profile} profile requires --manifest")
    if args.manifest is not None:
        manifest_payload = read_manifest(args.manifest)
        manifest_oracle_kinds = manifest_case_oracle_kinds(manifest_payload)
        manifest_summary, manifest_errors = audit_manifest(
            manifest=manifest_payload,
            manifest_path=args.manifest,
            expected_split_id=args.split.stem,
            case_ids=case_ids,
            known_cases=known_cases,
            profile=profile,
        )
        errors.extend(manifest_errors)

    case_reports: list[dict[str, Any]] = []
    if args.audit_cases and not missing_cases and not split_duplicates:
        for case_id in case_ids:
            report = audit_cases.audit_case(
                known_cases[case_id],
                smoke=args.smoke,
                root=root,
                oracle_kind=manifest_oracle_kinds.get(case_id),
            )
            case_reports.append(report)
        failed_cases = [report["case"] for report in case_reports if not report["passed"]]
        if failed_cases:
            errors.append(f"case audit failed: {', '.join(failed_cases)}")
        if manifest_payload is not None and profile in {"candidate", "clean60"}:
            audit_manifest_oracle_alignment(
                manifest=manifest_payload,
                case_reports=case_reports,
                errors=errors,
                label=profile,
            )

    passed = not errors
    return {
        "passed": passed,
        "split": str(args.split),
        "expected_count": expected_count,
        "profile": profile,
        "actual_count": len(case_ids),
        "duplicates": split_duplicates,
        "missing_cases": missing_cases,
        "overlap": overlap,
        "bpfix_bench_overlap": bpfix_bench_overlap,
        "near_duplicates": near_duplicates,
        "prior_eval_overlap": prior_eval_overlap,
        "manifest": manifest_summary,
        "audit": {
            "enabled": bool(args.audit_cases),
            "smoke": bool(args.smoke),
            "total": len(case_reports),
            "passed": sum(1 for report in case_reports if report["passed"]),
            "failed": sum(1 for report in case_reports if not report["passed"]),
            "reports": case_reports,
        },
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    summary = audit_split(parse_args(argv))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
