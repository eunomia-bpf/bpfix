#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import cleanup_pin, compile_bpf, load_bpf, normalize_load_output, parse_args, pin_name_for


EXPECTED_REJECT_SUBSTRINGS = [
    "Unreleased reference",
    "alloc_insn",
]

CUSTOM_ORACLE_COVERAGE = {
    "expected_reject_substrings": [
        "Unreleased reference",
        "alloc_insn",
    ],
    "required_success_substrings": [
        "sec 'tc'",
        "call bpf_skc_lookup_tcp#99",
        "call bpf_sk_assign#124",
        "call bpf_sk_release#86",
    ],
    "required_success_predicates": [
        "socket assignment helper order is preserved",
        "bpf_sk_assign receives the looked-up socket",
        "bpf_sk_release releases the looked-up socket after assignment",
    ],
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def releases_socket_before_return_branches(text: str) -> bool:
    assign = re.search(r"\bresult\s*=\s*bpf_sk_assign\s*\([^;]+;", text, flags=re.DOTALL)
    if assign is None:
        return False
    branch = re.search(r"\bif\s*\(\s*result\s*==\s*0\s*&&\s*skb\s*->\s*mark\s*==\s*PROXY_MARK\s*\)", text[assign.end() :])
    release = re.search(r"\bbpf_sk_release\s*\(\s*sk\s*\)\s*;", text[assign.end() :])
    return release is not None and (branch is None or release.start() < branch.start())


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        ("keeps TC section", 'SEC("tc")' in text),
        ("keeps tuple-based TCP socket lookup", re.search(r"\bbpf_skc_lookup_tcp\s*\(", text) is not None),
        ("keeps socket assignment", re.search(r"\bbpf_sk_assign\s*\(", text) is not None),
        ("keeps socket release", re.search(r"\bbpf_sk_release\s*\(", text) is not None),
        ("keeps marked-packet branch", re.search(r"\bskb\s*->\s*mark\s*==\s*PROXY_MARK\b", text) is not None),
        ("keeps current netns lookup", "BPF_F_CURRENT_NETNS" in text),
        ("keeps proxy port tuple", "PROXY_PORT" in text and "dport" in text),
        ("case source invariant A", releases_socket_before_return_branches(text)),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def helper_positions(load_output: str, helper: str) -> list[int]:
    return [match.start() for match in re.finditer(re.escape(helper), load_output)]


def helper_order_is_preserved(load_output: str) -> bool:
    lookup = load_output.find("call bpf_skc_lookup_tcp#99")
    assign = load_output.find("call bpf_sk_assign#124")
    release = load_output.find("call bpf_sk_release#86")
    return -1 not in {lookup, assign, release} and lookup < assign < release


def windows_before(load_output: str, helper: str, *, lines: int = 4) -> list[str]:
    split = load_output.splitlines()
    windows: list[str] = []
    for index, line in enumerate(split):
        if helper in line:
            windows.append("\n".join(split[max(0, index - lines) : index + 1]))
    return windows


def assign_receives_lookup_socket(load_output: str) -> bool:
    return any(
        "R2_w=sock_common" in context or "R2=sock_common" in context
        for context in windows_before(load_output, "call bpf_sk_assign#124", lines=5)
    )


def release_after_assign_uses_socket(load_output: str) -> bool:
    assign = load_output.find("call bpf_sk_assign#124")
    if assign == -1:
        return False
    return any(
        "R1_w=sock_common" in context or "R1=sock_common" in context
        for context in windows_before(load_output[assign:], "call bpf_sk_release#86", lines=5)
    )


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier loads TC program", "sec 'tc'" in load_output),
        ("verifier sees TCP socket lookup", "call bpf_skc_lookup_tcp#99" in load_output),
        ("verifier sees socket assignment", "call bpf_sk_assign#124" in load_output),
        ("verifier sees socket release", "call bpf_sk_release#86" in load_output),
        ("socket assignment helper order is preserved", helper_order_is_preserved(load_output)),
        ("bpf_sk_assign receives the looked-up socket", assign_receives_lookup_socket(load_output)),
        ("bpf_sk_release releases the looked-up socket after assignment", release_after_assign_uses_socket(load_output)),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    work_dir_obj: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir is None:
        work_dir_obj = tempfile.TemporaryDirectory(prefix="bpfix-test-")
        work_dir = Path(work_dir_obj.name)
    else:
        work_dir = args.work_dir
        work_dir.mkdir(parents=True, exist_ok=True)

    source = args.source.resolve()
    obj = work_dir / "prog.o"
    pin = Path("/sys/fs/bpf") / pin_name_for(source)
    report: dict[str, object] = {
        "source": str(source),
        "expect_reject": args.expect_reject,
        "compile": None,
        "load": None,
        "source_semantics": [],
        "load_log_semantics": [],
        "passed": False,
    }

    try:
        compile_result = compile_bpf(source, obj)
        report["compile"] = compile_result.to_json()
        if compile_result.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        load_result = load_bpf(obj, pin, prog_type=None)
        report["load"] = load_result.to_json()
        normalized = normalize_load_output(load_result.output, source=source, work_dir=work_dir, obj=obj, pin=pin)
        if args.save_log is not None:
            args.save_log.write_text(normalized, encoding="utf-8")

        if args.expect_reject:
            rejected = load_result.returncode != 0 and all(
                needle in load_result.output for needle in EXPECTED_REJECT_SUBSTRINGS
            )
            report["passed"] = rejected
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if rejected else 1

        if load_result.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        source_checks = source_semantics(source)
        load_checks = load_log_semantics(load_result.output)
        report["source_semantics"] = source_checks
        report["load_log_semantics"] = load_checks
        report["passed"] = all(check["passed"] for check in source_checks + load_checks)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 1
    finally:
        cleanup_pin(pin)
        if work_dir_obj is not None:
            work_dir_obj.cleanup()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
