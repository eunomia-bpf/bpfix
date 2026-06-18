#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import cleanup_pin, compile_bpf, load_bpf, normalize_load_output, parse_args, pin_name_for


MSG_DATA_ARG_LEN = 32
MSG_DATA_ARG_OFFSET = 8

EXPECTED_REJECT_SUBSTRINGS = [
    "R2 unbounded memory access",
]

CUSTOM_ORACLE_COVERAGE = {
    "expected_reject_substrings": [
        "R2 unbounded memory access",
    ],
    "required_success_substrings": [
        "sec 'tracepoint/syscalls/sys_enter_write'",
        "call bpf_map_lookup_elem#1",
        "call bpf_probe_read_user#112",
        "call bpf_perf_event_output#25",
    ],
    "required_success_predicates": [
        "data-event source workflow is preserved",
        "probe-read destination is the data_heap payload",
        "probe-read copy length is verifier-bounded by MSG_DATA_ARG_LEN",
        "perf-output data and size preserve the same bounded data-event payload",
    ],
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//.*", " ", text)


def source_semantics(source: Path) -> list[dict[str, object]]:
    text = strip_comments(source.read_text(encoding="utf-8"))
    checks = [
        ("keeps sys_enter_write tracepoint", 'SEC("tracepoint/syscalls/sys_enter_write")' in text),
        ("keeps map-backed data heap", "BPF_MAP_TYPE_ARRAY" in text and "data_heap" in text),
        ("keeps perf event output map", "BPF_MAP_TYPE_PERF_EVENT_ARRAY" in text and "events" in text),
        ("keeps syscall arg1 as user data source", "ctx->args[1]" in text),
        ("keeps syscall arg2 as requested copy size", "ctx->args[2]" in text),
        ("keeps explicit MSG_DATA_ARG_LEN guard", "MSG_DATA_ARG_LEN" in text and re.search(r">\s*MSG_DATA_ARG_LEN", text) is not None),
        ("keeps data-event byte copy", re.search(r"\bbpf_probe_read_user\s*\(", text) is not None),
        ("keeps perf event output", re.search(r"\bbpf_perf_event_output\s*\(", text) is not None),
        ("keeps data-event status descriptor", "struct data_event_desc" in text and "desc.size" in text),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def helper_windows(load_output: str, helper: str, *, lines: int = 7) -> list[str]:
    split = load_output.splitlines()
    return [
        "\n".join(split[max(0, index - lines) : index + 1])
        for index, line in enumerate(split)
        if helper in line and re.match(r"\s*\d+:\s+\([0-9a-fA-F]{2}\)\s+.*call", line)
    ]


def register_states(context: str, register: str) -> list[str]:
    return re.findall(rf"\bR{register}(?:_w)?=([^\s;]+)", context)


def last_register_state(context: str, register: str) -> str:
    states = register_states(context, register)
    return states[-1] if states else ""


def register_is_data_heap_value(state: str, *, offset: int | None = None) -> bool:
    if not state.startswith("map_value(map=data_heap,ks=4,vs=40"):
        return False
    if offset is None:
        return True
    return f"off={offset}" in state


def scalar_constant_value(state: str) -> int | None:
    return int(state, 0) if re.fullmatch(r"-?(?:0x[0-9a-fA-F]+|\d+)", state) else None


def scalar_upper_bound(state: str) -> int | None:
    constant = scalar_constant_value(state)
    if constant is not None:
        return constant
    maxima = [int(value, 0) for value in re.findall(r"\b(?:umax|smax|umax32|smax32)=(-?(?:0x[0-9a-fA-F]+|\d+))", state)]
    if not maxima:
        return None
    return max(maxima)


def scalar_id_expr(state: str) -> str | None:
    match = re.search(r"scalar\(id=([^,\)]+)", state)
    return match.group(1) if match else None


def annotated_contexts(load_output: str, helper: str, *, lines: int) -> list[str]:
    return [
        context
        for context in helper_windows(load_output, helper, lines=lines)
        if re.search(r"\bR\d+(?:_w)?=", context)
    ]


def probe_contexts(load_output: str) -> list[str]:
    return annotated_contexts(load_output, "call bpf_probe_read_user#112", lines=12)


def perf_contexts(load_output: str) -> list[str]:
    return annotated_contexts(load_output, "call bpf_perf_event_output#25", lines=16)


def probe_read_uses_data_heap_payload(load_output: str) -> bool:
    contexts = probe_contexts(load_output)
    return bool(contexts) and all(
        register_is_data_heap_value(last_register_state(context, "1"), offset=8)
        for context in contexts
    )


def bounded_probe_read_len(load_output: str) -> bool:
    contexts = probe_contexts(load_output)
    return bool(contexts) and all(
        (upper := scalar_upper_bound(last_register_state(context, "2"))) is not None and 0 <= upper <= MSG_DATA_ARG_LEN
        for context in contexts
    )


def perf_output_uses_bounded_size(load_output: str) -> bool:
    probes = probe_contexts(load_output)
    perfs = perf_contexts(load_output)
    if not probes or not perfs:
        return False

    if not all(register_is_data_heap_value(last_register_state(context, "4")) for context in perfs):
        return False

    saw_clamped_path = any(scalar_constant_value(last_register_state(context, "2")) == MSG_DATA_ARG_LEN for context in probes) and any(
        scalar_constant_value(last_register_state(context, "5")) == MSG_DATA_ARG_OFFSET + MSG_DATA_ARG_LEN
        for context in perfs
    )

    variable_probe_ids = {
        copy_id
        for context in probes
        if (copy_id := scalar_id_expr(last_register_state(context, "2"))) is not None
        and (upper := scalar_upper_bound(last_register_state(context, "2"))) is not None
        and upper < MSG_DATA_ARG_LEN
    }
    expected_size_ids = {f"{copy_id}+{MSG_DATA_ARG_OFFSET}" for copy_id in variable_probe_ids}
    saw_variable_path = any(
        any(
            scalar_id_expr(state) in expected_size_ids
            and (state_upper := scalar_upper_bound(state)) is not None
            and state_upper < MSG_DATA_ARG_OFFSET + MSG_DATA_ARG_LEN
            for state in register_states(context, "5")
        )
        and (final_upper := scalar_upper_bound(last_register_state(context, "5"))) is not None
        and final_upper < MSG_DATA_ARG_OFFSET + MSG_DATA_ARG_LEN
        for context in perfs
    )

    return saw_clamped_path and saw_variable_path


def helper_order_is_preserved(load_output: str) -> bool:
    lookup = load_output.find("call bpf_map_lookup_elem#1")
    probe = load_output.find("call bpf_probe_read_user#112")
    perf = load_output.find("call bpf_perf_event_output#25")
    return -1 not in {lookup, probe, perf} and lookup < probe < perf


def load_log_semantics(load_output: str) -> list[dict[str, object]]:
    checks = [
        ("verifier loads write tracepoint", "sec 'tracepoint/syscalls/sys_enter_write'" in load_output),
        ("verifier sees map lookup", "call bpf_map_lookup_elem#1" in load_output),
        ("verifier sees user-byte copy", "call bpf_probe_read_user#112" in load_output),
        ("verifier sees perf event output", "call bpf_perf_event_output#25" in load_output),
        ("helper order preserves Tetragon data-event workflow", helper_order_is_preserved(load_output)),
        ("probe-read destination is the data_heap payload", probe_read_uses_data_heap_payload(load_output)),
        ("probe-read copy length is verifier-bounded by MSG_DATA_ARG_LEN", bounded_probe_read_len(load_output)),
        ("perf-output data and size preserve the same bounded data-event payload", perf_output_uses_bounded_size(load_output)),
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
