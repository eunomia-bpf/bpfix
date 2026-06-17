#!/usr/bin/env python3
"""Check that the user-facing error catalog matches emitted CLI error IDs."""

from __future__ import annotations

import pathlib
import re
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "error-catalog.yaml"
SOURCE_FILES = sorted((ROOT / "crates" / "bpfix" / "src").rglob("*.rs"))
ERROR_ID_RE = re.compile(r"BPFIX-E\d{3}")


def main() -> int:
    catalog = yaml.safe_load(CATALOG.read_text())
    active = {
        entry["error_id"]
        for entry in catalog.get("active_error_ids", [])
        if isinstance(entry, dict)
    }
    historical = set(catalog.get("historical_error_ids", []))
    emitted = set()
    for path in SOURCE_FILES:
        emitted.update(ERROR_ID_RE.findall(path.read_text()))

    missing = sorted(emitted - active)
    stale_active = sorted(active - emitted)
    active_historical_overlap = sorted(active & historical)

    if missing or stale_active or active_historical_overlap:
        if missing:
            print("error catalog is missing emitted IDs:", ", ".join(missing), file=sys.stderr)
        if stale_active:
            print(
                "error catalog marks non-emitted IDs active:",
                ", ".join(stale_active),
                file=sys.stderr,
            )
        if active_historical_overlap:
            print(
                "error catalog IDs cannot be both active and historical:",
                ", ".join(active_historical_overlap),
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
