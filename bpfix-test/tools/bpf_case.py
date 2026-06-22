#!/usr/bin/env python3
"""Shared oracle helpers for bpfix-test cases."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeAlias


MapUpdate: TypeAlias = tuple[str, bytes, bytes]
MapPostCheck: TypeAlias = tuple[str, Callable[[Path], bool]]
FunctionalTest: TypeAlias = (
    tuple[str, Callable[[], bytes], int]
    | tuple[str, Callable[[], bytes], int, list[MapUpdate]]
    | tuple[str, Callable[[], bytes], int, list[MapUpdate], list[MapPostCheck]]
)
SourcePredicate: TypeAlias = tuple[str, Callable[[Path], bool]]


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return self.stdout + self.stderr

    def to_json(self) -> dict[str, object]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def run(argv: list[str], *, timeout: int = 30) -> CommandResult:
    completed = subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return CommandResult(argv, completed.returncode, completed.stdout, completed.stderr)


def split_tool(env_name: str, default: str) -> list[str]:
    return shlex.split(os.environ.get(env_name, default))


def compile_bpf(source: Path, obj: Path) -> CommandResult:
    clang = split_tool("CLANG", "clang")
    argv = [
        *clang,
        "-target",
        "bpf",
        "-O2",
        "-g",
        "-I",
        "/usr/include",
        "-D__TARGET_ARCH_x86",
        "-c",
        str(source),
        "-o",
        str(obj),
    ]
    return run(argv)


def load_bpf(
    obj: Path,
    pin: Path,
    *,
    debug: bool = True,
    pin_maps: Path | None = None,
    prog_type: str | None = "xdp",
) -> CommandResult:
    bpftool = split_tool("BPFTOOL", "sudo bpftool")
    argv = [*bpftool]
    if debug:
        argv.append("-d")
    argv.extend(["prog", "load", str(obj), str(pin)])
    if prog_type is not None:
        argv.extend(["type", prog_type])
    if pin_maps is not None:
        argv.extend(["pinmaps", str(pin_maps)])
    return run(argv)


def run_pinned(pin: Path, data: bytes) -> tuple[int, CommandResult]:
    with tempfile.NamedTemporaryFile(prefix="bpfix-test-packet-", delete=False) as packet:
        packet.write(data)
        packet_path = Path(packet.name)
    try:
        bpftool = split_tool("BPFTOOL", "sudo bpftool")
        result = run(
            [
                *bpftool,
                "-j",
                "prog",
                "run",
                "pinned",
                str(pin),
                "data_in",
                str(packet_path),
                "repeat",
                "1",
            ]
        )
        if result.returncode != 0:
            return -1, result
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return -1, result
        return int(payload.get("retval", -1)), result
    finally:
        packet_path.unlink(missing_ok=True)


def prog_run_invalid_argument(result: CommandResult) -> bool:
    return result.returncode != 0 and "Invalid argument" in result.output


def cleanup_pin(pin: Path) -> None:
    run([*split_tool("PIN_RM", "sudo rm -f"), str(pin)], timeout=10)


def cleanup_pin_tree(path: Path) -> None:
    run([*split_tool("PIN_RM_TREE", "sudo rm -rf"), str(path)], timeout=10)


def ensure_pin_tree(path: Path) -> CommandResult:
    return run([*split_tool("PIN_MKDIR", "sudo mkdir -p"), str(path)], timeout=10)


def hex_bytes(data: bytes) -> list[str]:
    return [f"{byte:02x}" for byte in data]


def update_pinned_map(map_dir: Path, map_name: str, key: bytes, value: bytes) -> CommandResult:
    bpftool = split_tool("BPFTOOL", "sudo bpftool")
    return run(
        [
            *bpftool,
            "map",
            "update",
            "pinned",
            str(map_dir / map_name),
            "key",
            "hex",
            *hex_bytes(key),
            "value",
            "hex",
            *hex_bytes(value),
        ],
        timeout=10,
    )


def lookup_pinned_map(map_dir: Path, map_name: str, key: bytes) -> CommandResult:
    bpftool = split_tool("BPFTOOL", "sudo bpftool")
    return run(
        [
            *bpftool,
            "-j",
            "map",
            "lookup",
            "pinned",
            str(map_dir / map_name),
            "key",
            "hex",
            *hex_bytes(key),
        ],
        timeout=10,
    )


def lookup_pinned_map_value(map_dir: Path, map_name: str, key: bytes) -> tuple[bytes | None, CommandResult]:
    result = lookup_pinned_map(map_dir, map_name, key)
    if result.returncode != 0:
        return None, result
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, result
    value = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(value, list):
        return None, result
    try:
        return bytes(int(str(item), 0) for item in value), result
    except ValueError:
        return None, result


def functional_test_map_updates(test: FunctionalTest) -> list[MapUpdate]:
    return test[3] if len(test) >= 4 else []


def functional_test_post_checks(test: FunctionalTest) -> list[MapPostCheck]:
    return test[4] if len(test) == 5 else []


def pin_name_for(source: Path) -> str:
    safe_stem = re.sub(r"[^A-Za-z0-9_]+", "_", source.stem).strip("_")
    if not safe_stem:
        safe_stem = "candidate"
    return f"bpfix_test_{safe_stem}_{os.getpid()}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a bpfix-test case oracle.")
    parser.add_argument("--source", type=Path, required=True, help="Candidate BPF C source.")
    parser.add_argument("--work-dir", type=Path, help="Directory for temporary build artifacts.")
    parser.add_argument(
        "--expect-reject",
        action="store_true",
        help="Pass only if the source is rejected by the verifier.",
    )
    parser.add_argument("--save-log", type=Path, help="Write verifier load output to this file.")
    return parser.parse_args(argv)


def normalize_load_output(output: str, *, source: Path, work_dir: Path, obj: Path, pin: Path) -> str:
    normalized = output
    replacements = {
        str(source): "buggy.bpf.c",
        str(work_dir): "<work-dir>",
        str(obj): "<object>",
        str(pin): "<bpffs-pin>",
    }
    for old, new in replacements.items():
        normalized = normalized.replace(old, new)
    normalized = re.sub(r"/tmp/bpfix-test-[A-Za-z0-9_.-]+", "<work-dir>", normalized)
    normalized = re.sub(r"0xffff[0-9a-fA-F]+", "0xffff000000000000", normalized)
    normalized = re.sub(r"fd=\d+", "fd=0", normalized)
    normalized = re.sub(r"verification time \d+ usec", "verification time 0 usec", normalized)
    return normalized


def evaluate_success_log_checks(
    load_result: CommandResult,
    required_success_substrings: list[str],
    required_success_predicates: list[tuple[str, Callable[[str], bool]]],
) -> list[dict[str, object]]:
    output = load_result.output
    checks: list[dict[str, object]] = [
        {
            "kind": "substring",
            "name": needle,
            "passed": needle in output,
        }
        for needle in required_success_substrings
    ]
    for name, predicate in required_success_predicates:
        try:
            passed = predicate(output)
            error = None
        except Exception as exc:  # pragma: no cover - defensive oracle reporting
            passed = False
            error = str(exc)
        check: dict[str, object] = {
            "kind": "predicate",
            "name": name,
            "passed": bool(passed),
        }
        if error is not None:
            check["error"] = error
        checks.append(check)
    return checks


def evaluate_source_checks(source: Path, predicates: list[SourcePredicate]) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    for name, predicate in predicates:
        try:
            passed = predicate(source)
            error = None
        except Exception as exc:  # pragma: no cover - defensive oracle reporting
            passed = False
            error = str(exc)
        check: dict[str, object] = {
            "kind": "source_predicate",
            "name": name,
            "passed": bool(passed),
        }
        if error is not None:
            check["error"] = error
        checks.append(check)
    return checks


def ringbuf_refs_for_register(state: str, register: str, *, expected_size: int = 4) -> set[str]:
    return set(
        ref
        for ref, size in re.findall(rf"\bR{register}(?:_w)?=ringbuf_mem\(ref_obj_id=(\d+),sz=(\d+)\)", state)
        if int(size) == expected_size
    )


def map_value_register_updates(state: str) -> dict[str, bool]:
    updates: dict[str, bool] = {}
    for register, value in re.findall(r"\bR(\d+)(?:_w)?=([^\s;]+)", state):
        updates[register] = value.startswith("map_value(")
    return updates


def packet_register_updates(state: str) -> dict[str, bool]:
    updates: dict[str, bool] = {}
    for register, value in re.findall(r"\bR(\d+)(?:_w)?=([^\s;]+)", state):
        updates[register] = value.startswith("pkt(")
    return updates


def packet_register_state_updates(state: str) -> dict[str, str | None]:
    updates: dict[str, str | None] = {}
    for register, value in re.findall(r"\bR(\d+)(?:_w)?=([^\s;]+)", state):
        updates[register] = value if value.startswith("pkt(") else None
    return updates


def packet_state_has_variable_offset(state: str) -> bool:
    return "var_off=" in state or re.search(r"\bumax=[1-9]\d*", state) is not None


def packet_register_offsets(state: str) -> dict[str, int]:
    offsets: dict[str, int] = {}
    for register, value in re.findall(r"\bR(\d+)(?:_w)?=([^\s;]+)", state):
        if not value.startswith("pkt("):
            continue
        offset = re.search(r"\boff=(-?\d+)", value)
        offsets[register] = int(offset.group(1)) if offset is not None else 0
    return offsets


def scalar_values_for_register(state: str, register: str) -> set[int]:
    values: set[int] = set()
    for raw in re.findall(rf"\bR{register}(?:_w)?=(-?(?:0x[0-9a-fA-F]+|\d+))\b", state):
        values.add(int(raw, 0))
    return values


def ringbuf_written_refs_before_helper(
    load_output: str,
    helper_call: str,
    *,
    expected_u32_values: set[int] | None = None,
    expected_store_offset: int = 0,
    expected_ringbuf_size: int = 4,
) -> bool:
    in_annotated_trace = False
    written_refs: set[str] = set()
    r1_refs: set[str] = set()
    saw_helper = False
    for line in load_output.splitlines():
        if not line.strip():
            written_refs = set()
            r1_refs = set()
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
            written_refs = set()
            r1_refs = ringbuf_refs_for_register(line, "1", expected_size=expected_ringbuf_size)
            continue
        if line.startswith("from "):
            written_refs = set()
            r1_refs = ringbuf_refs_for_register(line, "1", expected_size=expected_ringbuf_size)
            continue
        if not in_annotated_trace:
            continue

        state = line
        if re.search(r"\bR1(?:_w)?=", state):
            r1_refs = ringbuf_refs_for_register(state, "1", expected_size=expected_ringbuf_size)
        if helper_call in line:
            saw_helper = True
            if not r1_refs or not (written_refs & r1_refs):
                return False

        store = re.search(r"\*\(u32 \*\)\(r(\d+)\s*([+-])\s*(\d+)\)\s*=\s*r(\d+)", line)
        if store is not None:
            sign = -1 if store.group(2) == "-" else 1
            store_offset = sign * int(store.group(3))
            stored_values = scalar_values_for_register(state, store.group(4))
            if store_offset == expected_store_offset and (
                expected_u32_values is None or bool(expected_u32_values & stored_values)
            ):
                written_refs.update(
                    ringbuf_refs_for_register(state, store.group(1), expected_size=expected_ringbuf_size)
                )
    return saw_helper


def ringbuf_refs_written_with_u32_value(
    load_output: str,
    expected_value: int,
    *,
    expected_store_offset: int = 0,
    expected_ringbuf_size: int = 4,
) -> set[str]:
    in_annotated_trace = False
    written_refs: set[str] = set()
    for line in load_output.splitlines():
        if line.startswith("0: R1="):
            in_annotated_trace = True
            continue
        if not in_annotated_trace:
            continue

        store = re.search(r"\*\(u32 \*\)\(r(\d+)\s*([+-])\s*(\d+)\)\s*=\s*r(\d+)", line)
        if store is None:
            continue

        sign = -1 if store.group(2) == "-" else 1
        store_offset = sign * int(store.group(3))
        if store_offset != expected_store_offset:
            continue
        if expected_value not in scalar_values_for_register(line, store.group(4)):
            continue
        written_refs.update(ringbuf_refs_for_register(line, store.group(1), expected_size=expected_ringbuf_size))
    return written_refs


def submitted_ringbuf_refs(
    load_output: str,
    *,
    helper_call: str = "call bpf_ringbuf_submit#132",
    expected_ringbuf_size: int = 4,
) -> set[str]:
    in_annotated_trace = False
    r1_refs: set[str] = set()
    submitted_refs: set[str] = set()
    for line in load_output.splitlines():
        if not line.strip():
            r1_refs = set()
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
            r1_refs = ringbuf_refs_for_register(line, "1", expected_size=expected_ringbuf_size)
            continue
        if line.startswith("from "):
            r1_refs = ringbuf_refs_for_register(line, "1", expected_size=expected_ringbuf_size)
            continue
        if not in_annotated_trace:
            continue

        if re.search(r"\bR1(?:_w)?=", line):
            r1_refs = ringbuf_refs_for_register(line, "1", expected_size=expected_ringbuf_size)
        if helper_call in line:
            submitted_refs.update(r1_refs)
    return submitted_refs


def helper_calls_use_register_value(load_output: str, helper_call: str, register: str, expected_value: int) -> bool:
    in_annotated_trace = False
    register_values: set[int] = set()
    saw_helper = False
    for line in load_output.splitlines():
        if not line.strip() or line.startswith("from "):
            register_values = set()
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
            register_values = scalar_values_for_register(line, register)
            continue
        if not in_annotated_trace:
            continue

        if re.search(rf"\bR{register}(?:_w)?=", line):
            register_values = scalar_values_for_register(line, register)
        if helper_call in line:
            saw_helper = True
            if expected_value not in register_values:
                return False
    return saw_helper


def helper_reachable_with_register_value(
    load_output: str,
    helper_call: str,
    register: str,
    expected_value: int,
) -> bool:
    in_annotated_trace = False
    register_values: set[int] = set()
    for line in load_output.splitlines():
        if not line.strip():
            register_values = set()
            continue
        if line.startswith("0: R1=") or line.startswith("from "):
            in_annotated_trace = True
            register_values = scalar_values_for_register(line, register)
            continue
        if not in_annotated_trace:
            continue

        values = scalar_values_for_register(line, register)
        if values:
            register_values = values
        if helper_call in line and expected_value in register_values:
            return True
    return False


def xdp_adjust_head_called_with_delta14(load_output: str) -> bool:
    return helper_calls_use_register_value(load_output, "call bpf_xdp_adjust_head#44", "2", 14)


def loaded_map_value_u32_offset(load_output: str, offset: int) -> bool:
    in_annotated_trace = False
    map_value_registers: set[str] = set()
    for line in load_output.splitlines():
        if not line.strip():
            map_value_registers = set()
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
            map_value_registers = {
                register for register, is_map_value in map_value_register_updates(line).items() if is_map_value
            }
            continue
        if not in_annotated_trace:
            continue
        load = re.search(rf"=\s*\*\(u32 \*\)\(r(\d+)\s*\+\s*{offset}\)", line)
        if load is not None and load.group(1) in map_value_registers:
            return True
        for register, is_map_value in map_value_register_updates(line).items():
            if is_map_value:
                map_value_registers.add(register)
            else:
                map_value_registers.discard(register)
    return False


def stored_map_value_u32_offset(load_output: str, offset: int) -> bool:
    in_annotated_trace = False
    map_value_registers: set[str] = set()
    for line in load_output.splitlines():
        if not line.strip():
            map_value_registers = set()
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
            map_value_registers = {
                register for register, is_map_value in map_value_register_updates(line).items() if is_map_value
            }
            continue
        if not in_annotated_trace:
            continue
        line_map_values = {
            register for register, is_map_value in map_value_register_updates(line).items() if is_map_value
        }
        store = re.search(rf"\*\(u32 \*\)\(r(\d+)\s*\+\s*{offset}\)\s*=\s*r\d+", line)
        if store is not None and (store.group(1) in map_value_registers or store.group(1) in line_map_values):
            return True
        for register, is_map_value in map_value_register_updates(line).items():
            if is_map_value:
                map_value_registers.add(register)
            else:
                map_value_registers.discard(register)
    return False


def loaded_map_value_u32_offset0(load_output: str) -> bool:
    return loaded_map_value_u32_offset(load_output, 0)


def loaded_map_value_u32_offset4(load_output: str) -> bool:
    return loaded_map_value_u32_offset(load_output, 4)


def stored_map_value_u32_offset4(load_output: str) -> bool:
    return stored_map_value_u32_offset(load_output, 4)


def packet_store_after_helper_call(
    load_output: str,
    helper_call: str,
    *,
    store_width: str,
    expected_store_offset: int,
    expected_values: set[int] | None = None,
) -> bool:
    in_annotated_trace = False
    saw_helper = False
    packet_offsets: dict[str, int] = {}
    store_re = re.compile(
        rf"\*\({re.escape(store_width)} \*\)\(r(\d+)\s*([+-])\s*(\d+)\)\s*=\s*r(\d+)"
    )

    for line in load_output.splitlines():
        if not line.strip():
            packet_offsets = {}
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
            packet_offsets = packet_register_offsets(line)
            continue
        if not in_annotated_trace:
            continue

        if helper_call in line:
            saw_helper = True
            packet_offsets = {}
            continue
        if not saw_helper:
            continue

        line_packet_offsets = packet_register_offsets(line)
        for register, is_packet in packet_register_updates(line).items():
            if is_packet:
                packet_offsets[register] = line_packet_offsets.get(register, 0)
            else:
                packet_offsets.pop(register, None)

        store = store_re.search(line)
        if store is None:
            continue
        sign = -1 if store.group(2) == "-" else 1
        store_offset = sign * int(store.group(3))
        base_offset = packet_offsets.get(store.group(1))
        if base_offset is None or base_offset + store_offset != expected_store_offset:
            continue
        if expected_values is None or expected_values & scalar_values_for_register(line, store.group(4)):
            return True
    return False


def packet_eth_proto_store_after_skb_change_proto(load_output: str) -> bool:
    return packet_store_after_helper_call(
        load_output,
        "call bpf_skb_change_proto#31",
        store_width="u16",
        expected_store_offset=12,
        expected_values={8},
    )


def packet_u16_load_from_variable_offset(load_output: str) -> bool:
    in_annotated_trace = False
    saw_ihl_scale = False
    packet_states: dict[str, str] = {}

    for line in load_output.splitlines():
        if not line.strip():
            packet_states = {}
            continue
        if line.startswith("0: R1="):
            in_annotated_trace = True
        if not in_annotated_trace:
            continue

        if re.search(r"\br\d+\s*<<=\s*2\b", line):
            saw_ihl_scale = True

        load = re.search(r"=\s*\*\(u16 \*\)\(r(\d+)\s*\+\s*2\)", line)
        state = packet_states.get(load.group(1)) if load is not None and saw_ihl_scale else None
        if state is not None and packet_state_has_variable_offset(state):
            return True

        for register, updated_state in packet_register_state_updates(line).items():
            if updated_state is None:
                packet_states.pop(register, None)
            else:
                packet_states[register] = updated_state
    return False


def submitted_written_ringbuf_record(load_output: str) -> bool:
    return ringbuf_written_refs_before_helper(load_output, "call bpf_ringbuf_submit#132")


def discarded_written_ringbuf_record(load_output: str) -> bool:
    return ringbuf_written_refs_before_helper(load_output, "call bpf_ringbuf_discard#133")


def submitted_ringbuf_record_with_mark7(load_output: str) -> bool:
    return bool(ringbuf_refs_written_with_u32_value(load_output, 7) & submitted_ringbuf_refs(load_output))


def submitted_ringbuf_record_with_mark11(load_output: str) -> bool:
    return bool(ringbuf_refs_written_with_u32_value(load_output, 11) & submitted_ringbuf_refs(load_output))


def ringbuf_reserve_reachable_with_mark7(load_output: str) -> bool:
    return helper_reachable_with_register_value(load_output, "call bpf_ringbuf_reserve#131", "7", 7)


def submitted_ringbuf_record_with_mark3_any_path(load_output: str) -> bool:
    return bool(ringbuf_refs_written_with_u32_value(load_output, 3) & submitted_ringbuf_refs(load_output))


def submitted_ringbuf_record_with_mark11_any_path(load_output: str) -> bool:
    return bool(ringbuf_refs_written_with_u32_value(load_output, 11) & submitted_ringbuf_refs(load_output))


def ringbuf_record_written_with_mark7(load_output: str) -> bool:
    return bool(ringbuf_refs_written_with_u32_value(load_output, 7))


def submitted_at_least_two_distinct_ringbuf_records(load_output: str) -> bool:
    return len(submitted_ringbuf_refs(load_output)) >= 2


def discarded_ringbuf_record_with_mark7(load_output: str) -> bool:
    return bool(
        ringbuf_refs_written_with_u32_value(load_output, 7)
        & submitted_ringbuf_refs(load_output, helper_call="call bpf_ringbuf_discard#133")
    )


def submitted_ringbuf_record_with_mark7_or_11(load_output: str) -> bool:
    written = ringbuf_refs_written_with_u32_value(load_output, 7) | ringbuf_refs_written_with_u32_value(load_output, 11)
    return bool(written & submitted_ringbuf_refs(load_output))


def run_case(
    *,
    argv: list[str] | None,
    expected_reject_substrings: list[str],
    functional_tests: list[FunctionalTest],
    required_success_substrings: list[str] | None = None,
    required_success_predicates: list[tuple[str, Callable[[str], bool]]] | None = None,
    source_success_predicates: list[SourcePredicate] | None = None,
    map_updates: list[MapUpdate] | None = None,
    prog_type: str | None = "xdp",
) -> int:
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
    needs_pinned_maps = bool(map_updates) or any(
        functional_test_map_updates(test) or functional_test_post_checks(test)
        for test in functional_tests
    )
    map_pin_dir = Path("/sys/fs/bpf") / f"{pin.name}_maps" if needs_pinned_maps else None

    report: dict[str, object] = {
        "source": str(source),
        "expect_reject": args.expect_reject,
        "compile": None,
        "load": None,
        "map_setup": [],
        "source_semantics": [],
        "functional": [],
        "success_log_checks": [],
        "passed": False,
    }

    try:
        compile_result = compile_bpf(source, obj)
        report["compile"] = compile_result.to_json()
        if compile_result.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        if map_pin_dir is not None:
            mkdir_result = ensure_pin_tree(map_pin_dir)
            report["map_setup"] = [mkdir_result.to_json()]
            if mkdir_result.returncode != 0:
                print(json.dumps(report, indent=2, sort_keys=True))
                return 1

        load_result = load_bpf(obj, pin, pin_maps=map_pin_dir, prog_type=prog_type)
        report["load"] = load_result.to_json()
        if args.save_log is not None:
            args.save_log.write_text(
                normalize_load_output(load_result.output, source=source, work_dir=work_dir, obj=obj, pin=pin),
                encoding="utf-8",
            )

        if args.expect_reject:
            output = load_result.output
            rejected = load_result.returncode != 0 and all(
                needle in output for needle in expected_reject_substrings
            )
            report["passed"] = rejected
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if rejected else 1

        if load_result.returncode != 0:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        if map_pin_dir is not None:
            setup_results = report["map_setup"]
            assert isinstance(setup_results, list)
            for map_name, key, value in map_updates or []:
                update_result = update_pinned_map(map_pin_dir, map_name, key, value)
                setup_results.append(update_result.to_json())
                if update_result.returncode != 0:
                    print(json.dumps(report, indent=2, sort_keys=True))
                    return 1

        required = required_success_substrings or []
        predicates = required_success_predicates or []
        checks = evaluate_success_log_checks(load_result, required, predicates)
        report["success_log_checks"] = checks
        if not all(check["passed"] for check in checks):
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        source_checks = evaluate_source_checks(source, source_success_predicates or [])
        report["source_semantics"] = source_checks
        if not all(check["passed"] for check in source_checks):
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1

        functional_results: list[dict[str, object]] = []
        ok = True
        for test in functional_tests:
            name, packet_fn, expected_retval = test[:3]
            per_test_map_updates = functional_test_map_updates(test)
            map_update_results = []
            if per_test_map_updates:
                assert map_pin_dir is not None
                for map_name, key, value in per_test_map_updates:
                    update_result = update_pinned_map(map_pin_dir, map_name, key, value)
                    map_update_results.append(update_result.to_json())
                    if update_result.returncode != 0:
                        functional_results.append(
                            {
                                "name": name,
                                "expected_retval": expected_retval,
                                "actual_retval": None,
                                "passed": False,
                                "map_updates": map_update_results,
                            }
                        )
                        ok = False
                        break
                if not ok:
                    break
            retval, prog_run = run_pinned(pin, packet_fn())
            post_check_results: list[dict[str, object]] = []
            post_checks = functional_test_post_checks(test)
            post_checks_passed = True
            if post_checks:
                assert map_pin_dir is not None
                for check_name, check_fn in post_checks:
                    try:
                        check_passed = bool(check_fn(map_pin_dir))
                        error = None
                    except Exception as exc:  # pragma: no cover - defensive oracle reporting
                        check_passed = False
                        error = str(exc)
                    post_check: dict[str, object] = {
                        "name": check_name,
                        "passed": check_passed,
                    }
                    if error is not None:
                        post_check["error"] = error
                    post_check_results.append(post_check)
                    post_checks_passed = post_checks_passed and check_passed
            invalid_short_packet_pass = (
                expected_retval == 2 and retval == -1 and prog_run_invalid_argument(prog_run)
            )
            passed = (retval == expected_retval or invalid_short_packet_pass) and post_checks_passed
            functional_results.append(
                {
                    "name": name,
                    "expected_retval": expected_retval,
                    "actual_retval": retval,
                    "passed": passed,
                    "run_error_treated_as_pass": invalid_short_packet_pass,
                    "map_updates": map_update_results,
                    "post_run_checks": post_check_results,
                    "run": prog_run.to_json(),
                }
            )
            ok = ok and passed
        report["functional"] = functional_results
        report["passed"] = ok
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if ok else 1
    finally:
        cleanup_pin(pin)
        if map_pin_dir is not None:
            cleanup_pin_tree(map_pin_dir)
        if work_dir_obj is not None:
            work_dir_obj.cleanup()


if __name__ == "__main__":
    print("Import this module from a case test.py.", file=sys.stderr)
    raise SystemExit(2)
