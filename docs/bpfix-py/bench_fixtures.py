"""Shared test helpers for the canonical bpfix-bench layout."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


ARCHIVE_ROOT = Path(__file__).resolve().parent
ROOT = ARCHIVE_ROOT.parents[1]
RAW_EXTERNAL_PARTS = ("bpfix-bench", "raw")


def resolve_case_path(path_or_id: str | Path) -> Path:
    raw = Path(path_or_id)
    text = str(path_or_id)
    if raw.is_absolute():
        return raw

    if text.startswith("stackoverflow-"):
        return ROOT / "bpfix-bench" / "raw" / "so" / f"{text}.yaml"
    if text.startswith("github-"):
        return ROOT / "bpfix-bench" / "raw" / "gh" / f"{text}.yaml"
    if text.startswith("kernel-selftest-"):
        return ROOT / "bpfix-bench" / "raw" / "kernel_selftests" / f"{text}.yaml"

    return ROOT / raw


def load_case(path_or_id: str | Path) -> dict[str, Any]:
    path = resolve_case_path(path_or_id)
    return _load_case_from_path(str(path))


@lru_cache(maxsize=None)
def _load_case_from_path(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not contain a YAML mapping")
    return payload


def raw_payload(case_data: dict[str, Any]) -> dict[str, Any]:
    if case_data.get("schema_version") == "bpfix.raw_external/v1":
        raw = case_data.get("raw")
        return raw if isinstance(raw, dict) else {}
    return case_data


def verifier_log_from_case(case_data: dict[str, Any], *, block_index: int | None = None) -> str:
    payload = raw_payload(case_data)
    verifier_log = payload.get("original_verifier_log", payload.get("verifier_log"))
    if isinstance(verifier_log, str):
        if block_index not in (None, 0):
            raise IndexError(block_index)
        return verifier_log
    if not isinstance(verifier_log, dict):
        return ""
    if block_index is not None:
        blocks = verifier_log.get("blocks") or []
        return blocks[block_index]
    combined = verifier_log.get("combined")
    if isinstance(combined, str) and combined.strip():
        return combined
    blocks = verifier_log.get("blocks") or []
    return "\n\n".join(block for block in blocks if isinstance(block, str))


def load_verifier_log(path_or_id: str | Path) -> str:
    path = resolve_case_path(path_or_id)
    raw_logs = extract_raw_verifier_logs(path)
    if raw_logs is not None:
        return raw_logs["combined"]
    return verifier_log_from_case(load_case(path_or_id))


def load_verifier_block(path_or_id: str | Path, index: int) -> str:
    path = resolve_case_path(path_or_id)
    raw_logs = extract_raw_verifier_logs(path)
    if raw_logs is not None:
        return raw_logs["blocks"][index]
    return verifier_log_from_case(load_case(path_or_id), block_index=index)


@lru_cache(maxsize=None)
def extract_raw_verifier_logs(path: Path) -> dict[str, Any] | None:
    try:
        relative = path.resolve().relative_to(ROOT)
    except ValueError:
        return None
    parts = relative.parts
    if len(parts) < 4 or parts[:2] != RAW_EXTERNAL_PARTS or parts[2] not in {"so", "gh"}:
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    for key in ("original_verifier_log", "verifier_log"):
        section = _extract_top_level_raw_section(text, key)
        if section is None:
            continue
        blocks = _extract_literal_sequence(section, "blocks")
        combined = _extract_literal_scalar(section, "combined")
        if not combined and blocks:
            combined = "\n\n".join(blocks)
        if combined or blocks:
            return {"combined": combined, "blocks": blocks or [combined]}
    return None


def _extract_top_level_raw_section(text: str, key: str) -> list[str] | None:
    lines = text.splitlines()
    start = None
    prefix = f"  {key}:"
    for index, line in enumerate(lines):
        if line == prefix:
            start = index + 1
            break
    if start is None:
        return None

    end = len(lines)
    for index in range(start, len(lines)):
        line = lines[index]
        if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
            end = index
            break
    return lines[start:end]


def _extract_literal_sequence(section: list[str], key: str) -> list[str]:
    blocks: list[str] = []
    in_sequence = False
    index = 0
    while index < len(section):
        line = section[index]
        if line == f"    {key}:":
            in_sequence = True
            index += 1
            continue
        if in_sequence and line.startswith("    ") and not line.startswith("      ") and line != "    - |-":
            break
        if in_sequence and line == "    - |-":
            block, index = _collect_literal_block(section, index + 1)
            blocks.append(block)
            continue
        index += 1
    return blocks


def _extract_literal_scalar(section: list[str], key: str) -> str:
    for index, line in enumerate(section):
        if line == f"    {key}: |-":
            block, _ = _collect_literal_block(section, index + 1)
            return block
    return ""


def _collect_literal_block(lines: list[str], start: int) -> tuple[str, int]:
    content: list[str] = []
    index = start
    while index < len(lines):
        line = lines[index]
        if line and not line.startswith("      "):
            break
        content.append(line[6:] if line.startswith("      ") else "")
        index += 1
    return "\n".join(content), index
