#!/usr/bin/env python3
"""Run BPFix over the checked-in bpfix-empirical corpus."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


def repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bpfix-bin",
        type=pathlib.Path,
        help="Path to an existing bpfix binary. Defaults to target/debug/bpfix.",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Do not run cargo build before evaluating.",
    )
    parser.add_argument(
        "--release",
        action="store_true",
        help="Build and run target/release/bpfix instead of target/debug/bpfix.",
    )
    parser.add_argument(
        "--confusion",
        action="store_true",
        help="Print taxonomy confusion matrices after the metric summary.",
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Print proof-action, localization, and optional object-analysis coverage tables.",
    )
    parser.add_argument(
        "--object-if-available",
        action="store_true",
        help="Build with object-analysis and pass each case's prog.o to bpfix when present.",
    )
    parser.add_argument(
        "--sample-audit",
        action="store_true",
        help="Print the deterministic stratified audit sample.",
    )
    parser.add_argument(
        "--reject-fallback",
        action="store_true",
        help="Exit non-zero if any replay case emits UNKNOWN, input_error, or unsupported diagnostics.",
    )
    parser.add_argument("--sample-size", default=80, type=int)
    parser.add_argument("--sample-seed", default="bpfix-eval-v1")
    return parser.parse_args()


def default_bpfix_bin(root: pathlib.Path, release: bool) -> pathlib.Path:
    profile = "release" if release else "debug"
    return root / "target" / profile / "bpfix"


def main() -> int:
    args = parse_args()
    root = repo_root()
    empirical_root = pathlib.Path(__file__).resolve().parent

    bpfix_bin = args.bpfix_bin
    if bpfix_bin is None:
        bpfix_bin = default_bpfix_bin(root, args.release)
    elif not bpfix_bin.is_absolute():
        bpfix_bin = (pathlib.Path.cwd() / bpfix_bin).resolve()

    if not args.no_build:
        build_cmd = ["cargo", "build", "-p", "bpfix"]
        if args.release:
            build_cmd.append("--release")
        if args.object_if_available and args.bpfix_bin is None:
            build_cmd.extend(["--features", "object-analysis"])
        subprocess.run(build_cmd, cwd=root, check=True)

    eval_script = root / "docs" / "evaluation" / "evaluate_diagnostics.py"
    eval_cmd = [
        sys.executable,
        str(eval_script),
        "--empirical-root",
        str(empirical_root),
        "--bpfix-bin",
        str(bpfix_bin),
    ]
    if args.confusion:
        eval_cmd.append("--confusion")
    if args.coverage:
        eval_cmd.append("--coverage")
    if args.object_if_available:
        eval_cmd.append("--object-if-available")
    if args.sample_audit:
        eval_cmd.append("--sample-audit")
    if args.reject_fallback:
        eval_cmd.append("--reject-fallback")
    eval_cmd.extend(["--sample-size", str(args.sample_size)])
    eval_cmd.extend(["--sample-seed", args.sample_seed])

    completed = subprocess.run(eval_cmd, cwd=root)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
