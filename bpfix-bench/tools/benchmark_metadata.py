"""Shared benchmark metadata helpers."""

from __future__ import annotations

import copy
from typing import Any


def with_case_defaults(case_data: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Return case metadata with manifest-level defaults filled in."""
    merged = copy.deepcopy(case_data)
    defaults = _case_defaults(manifest)
    for section_name, section_defaults in defaults.items():
        if not isinstance(section_defaults, dict):
            continue
        section = merged.get(section_name)
        if section is None:
            section = {}
        if not isinstance(section, dict):
            continue
        section = dict(section)
        for key, value in section_defaults.items():
            section.setdefault(key, value)
        merged[section_name] = section
    return merged


def _case_defaults(manifest: dict[str, Any]) -> dict[str, Any]:
    defaults = copy.deepcopy(manifest.get("case_defaults") or {})
    capture_defaults = defaults.setdefault("capture", {})
    if isinstance(capture_defaults, dict) and manifest.get("environment_id"):
        capture_defaults.setdefault("environment_id", manifest["environment_id"])
    return defaults
