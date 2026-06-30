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
    "bpfix-empirical/**/*.md",
    "examples/**/*.md",
    "skills/**/*.md",
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

REMOVED_LEGACY_BENCHMARK_TOOLS = [
    ROOT / "bpfix-bench" / "tools" / "audit_splits.py",
]

BANNED_BENCH_TERMS = [
    "docs/tmp",
    "clean60",
    "heldout",
    "working suite",
]

README_QUICK_START_ORDER = [
    "```bash\ncargo install bpfix\nsudo bpftool -d prog load examples/bpftool/quick-start.bpf.o /sys/fs/bpf/bpfix-demo 2>&1 | tee verifier.log\n```",
    "```bash\nbpfix verifier.log\n```",
    "The raw log says where the verifier stopped, but not the source-level proof",
    "error[BPFIX-E006]: verifier-visible compiler lowering hides the required proof",
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

    for path in REMOVED_LEGACY_BENCHMARK_TOOLS:
        if path.exists():
            errors.append(
                f"{path.relative_to(ROOT)} is a legacy split-staging tool; "
                "use audit_cases.py for the frozen main75 benchmark contract"
            )


def check_readme_quick_start(errors: list[str]) -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    cursor = 0
    for expected in README_QUICK_START_ORDER:
        index = text.find(expected, cursor)
        if index == -1:
            errors.append(
                "README.md Quick Start is missing or reordered around "
                f"{expected.splitlines()[0]!r}"
            )
            return
        cursor = index + len(expected)


def main() -> int:
    errors: list[str] = []
    check_links(errors)
    check_benchmark_contract_terms(errors)
    check_readme_quick_start(errors)
    if errors:
        print("documentation drift check failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
