#!/usr/bin/env python3
"""Check public Markdown docs for stale links and benchmark-contract drift."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]

PUBLIC_MARKDOWN_GLOBS = [
    "README.md",
    "docs/**/*.md",
    "bpfix-bench/**/*.md",
    "examples/**/*.md",
]

IGNORED_PARTS = {
    ".git",
    "target",
    "vendor",
}

LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")

BENCH_CONTRACT_DOCS = [
    ROOT / "README.md",
    ROOT / "bpfix-bench" / "README.md",
    ROOT / "bpfix-bench" / "splits" / "README.md",
    ROOT / "docs" / "evaluation" / "bpfix-bench-llm-repair-eval.md",
]

BANNED_BENCH_TERMS = [
    "docs/tmp",
    "clean60",
    "heldout",
    "working suite",
]


def iter_public_markdown() -> list[pathlib.Path]:
    paths: set[pathlib.Path] = set()
    for pattern in PUBLIC_MARKDOWN_GLOBS:
        paths.update(ROOT.glob(pattern))
    return sorted(
        path
        for path in paths
        if path.is_file() and not (set(path.relative_to(ROOT).parts) & IGNORED_PARTS)
    )


def normalize_link(raw: str) -> str | None:
    target = raw.strip()
    if not target:
        return None
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    else:
        target = target.split()[0]
    if target.startswith(("http://", "https://", "mailto:", "#")):
        return None
    target = target.split("#", 1)[0].split("?", 1)[0]
    if not target:
        return None
    return target


def check_links(errors: list[str]) -> None:
    for path in iter_public_markdown():
        text = path.read_text(encoding="utf-8")
        for raw in LINK_RE.findall(text):
            target = normalize_link(raw)
            if target is None:
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                errors.append(f"{path.relative_to(ROOT)} links outside repo: {target}")
                continue
            if not resolved.exists():
                errors.append(f"{path.relative_to(ROOT)} has broken link: {target}")


def check_benchmark_contract_terms(errors: list[str]) -> None:
    for path in BENCH_CONTRACT_DOCS:
        text = path.read_text(encoding="utf-8").lower()
        for term in BANNED_BENCH_TERMS:
            if term in text:
                errors.append(
                    f"{path.relative_to(ROOT)} mentions legacy benchmark term {term!r}"
                )


def main() -> int:
    errors: list[str] = []
    check_links(errors)
    check_benchmark_contract_terms(errors)
    if errors:
        print("documentation drift check failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
