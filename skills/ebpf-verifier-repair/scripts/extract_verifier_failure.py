#!/usr/bin/env python3
"""Extract the latest verifier load region and compact oversized traces."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


BEGIN_MARKER = "-- BEGIN PROG LOAD LOG --"
END_MARKER = "-- END PROG LOAD LOG --"
DEFAULT_MAX_CHARS = 48_000


def latest_load_region(text: str) -> str:
    begin = text.rfind(BEGIN_MARKER)
    if begin == -1:
        return text.strip() + "\n"
    line_begin = text.rfind("\n", 0, begin)
    line_begin = 0 if line_begin == -1 else line_begin + 1
    end = text.find(END_MARKER, begin)
    if end == -1:
        return text[line_begin:].strip() + "\n"
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    return text[line_begin:line_end].strip() + "\n"


def compact_verifier_log(text: str, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    if max_chars < 2_000:
        raise ValueError("max_chars must be at least 2000")
    region = latest_load_region(text)
    if len(region) <= max_chars:
        return region

    marker_template = (
        "\n... <omitted {omitted} chars; "
        "inspect the original log for intermediate PCs> ...\n"
    )
    marker = marker_template.format(omitted=len(region))
    head_budget = (max_chars - len(marker)) // 3
    tail_budget = max_chars - len(marker) - head_budget
    head_end = region.rfind("\n", 0, head_budget)
    head_end = head_budget if head_end == -1 else head_end + 1
    tail_start = region.find("\n", len(region) - tail_budget)
    tail_start = len(region) - tail_budget if tail_start == -1 else tail_start + 1
    omitted = max(0, tail_start - head_end)
    marker = marker_template.format(omitted=omitted)
    return region[:head_end] + marker + region[tail_start:]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="Verbose verifier or loader log.")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        text = args.log.read_text(encoding="utf-8", errors="replace")
        sys.stdout.write(compact_verifier_log(text, args.max_chars))
    except (OSError, ValueError) as exc:
        print(f"extract_verifier_failure.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
