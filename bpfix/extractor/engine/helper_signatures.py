"""Helper argument signatures keyed by stable UAPI helper IDs.

The helper IDs come from ``enum bpf_func_id`` in ``include/uapi/linux/bpf.h``.
This module keeps only ISA/UAPI-level helper contract data: helper number,
name, argument shape, and return shape. It intentionally does not parse
verifier reject text.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .opcode_safety import SafetyCondition


ArgSpec = dict[str, Any]
HelperSignature = dict[str, Any]


HELPER_SIGNATURES: dict[int, HelperSignature] = {
    1: {
        "name": "bpf_map_lookup_elem",
        "args": {
            "R1": {"type": "map_fd"},
            "R2": {"type": "ptr", "constraint": "key_size", "requires_range": True},
        },
        "ret": {"type": "ptr_or_null", "to": "map_value"},
    },
    2: {
        "name": "bpf_map_update_elem",
        "args": {
            "R1": {"type": "map_fd"},
            "R2": {"type": "ptr", "constraint": "key_size", "requires_range": True},
            "R3": {"type": "ptr", "constraint": "value_size", "requires_range": True},
            "R4": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "scalar"},
    },
    3: {
        "name": "bpf_map_delete_elem",
        "args": {
            "R1": {"type": "map_fd"},
            "R2": {"type": "ptr", "constraint": "key_size", "requires_range": True},
        },
        "ret": {"type": "scalar"},
    },
    4: {
        "name": "bpf_probe_read",
        "args": {
            "R1": {
                "type": "ptr",
                "constraint": "size_arg:R2",
                "requires_range": True,
                "writable": True,
            },
            "R2": {"type": "scalar", "constraint": "size"},
            "R3": {"type": "ptr", "constraint": "unsafe_ptr", "nullable": True},
        },
        "ret": {"type": "scalar"},
    },
    5: {"name": "bpf_ktime_get_ns", "args": {}, "ret": {"type": "scalar"}},
    12: {
        "name": "bpf_tail_call",
        "args": {
            "R1": {"type": "ctx"},
            "R2": {"type": "map_fd", "constraint": "prog_array"},
            "R3": {"type": "scalar", "constraint": "index"},
        },
        "ret": {"type": "scalar"},
    },
    14: {"name": "bpf_get_current_pid_tgid", "args": {}, "ret": {"type": "scalar"}},
    15: {"name": "bpf_get_current_uid_gid", "args": {}, "ret": {"type": "scalar"}},
    16: {
        "name": "bpf_get_current_comm",
        "args": {
            "R1": {
                "type": "ptr",
                "constraint": "size_arg:R2",
                "requires_range": True,
                "writable": True,
            },
            "R2": {"type": "scalar", "constraint": "size_of_buf"},
        },
        "ret": {"type": "scalar"},
    },
    22: {
        "name": "bpf_perf_event_read",
        "args": {
            "R1": {"type": "map_fd", "constraint": "perf_event_array"},
            "R2": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "scalar"},
    },
    25: {
        "name": "bpf_perf_event_output",
        "args": {
            "R1": {"type": "ctx"},
            "R2": {"type": "map_fd", "constraint": "perf_event_array"},
            "R3": {"type": "scalar", "constraint": "flags"},
            "R4": {"type": "ptr", "constraint": "size_arg:R5", "requires_range": True},
            "R5": {"type": "scalar", "constraint": "size"},
        },
        "ret": {"type": "scalar"},
    },
    26: {
        "name": "bpf_skb_load_bytes",
        "args": {
            "R1": {"type": "ctx"},
            "R2": {"type": "scalar", "constraint": "offset"},
            "R3": {
                "type": "ptr",
                "constraint": "size_arg:R4",
                "requires_range": True,
                "writable": True,
            },
            "R4": {"type": "scalar", "constraint": "len"},
        },
        "ret": {"type": "scalar"},
    },
    27: {
        "name": "bpf_get_stackid",
        "args": {
            "R1": {"type": "ctx"},
            "R2": {"type": "map_fd", "constraint": "stack_trace_map"},
            "R3": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "scalar"},
    },
    28: {
        "name": "bpf_csum_diff",
        "args": {
            "R1": {
                "type": "ptr",
                "constraint": "from_size",
                "requires_range": True,
                "nullable": True,
            },
            "R2": {"type": "scalar", "constraint": "from_size"},
            "R3": {
                "type": "ptr",
                "constraint": "to_size",
                "requires_range": True,
                "nullable": True,
            },
            "R4": {"type": "scalar", "constraint": "to_size"},
            "R5": {"type": "scalar", "constraint": "seed"},
        },
        "ret": {"type": "scalar"},
    },
    35: {
        "name": "bpf_get_current_task",
        "args": {},
        "ret": {"type": "trusted_ptr", "to": "task_struct"},
    },
    51: {
        "name": "bpf_redirect_map",
        "args": {
            "R1": {"type": "map_fd"},
            "R2": {"type": "scalar", "constraint": "key"},
            "R3": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "scalar"},
    },
    55: {
        "name": "bpf_perf_event_read_value",
        "args": {
            "R1": {"type": "map_fd", "constraint": "perf_event_array"},
            "R2": {"type": "scalar", "constraint": "flags"},
            "R3": {
                "type": "ptr",
                "constraint": "buf_size",
                "requires_range": True,
                "writable": True,
            },
            "R4": {"type": "scalar", "constraint": "buf_size"},
        },
        "ret": {"type": "scalar"},
    },
    67: {
        "name": "bpf_get_stack",
        "args": {
            "R1": {"type": "ctx"},
            "R2": {
                "type": "ptr",
                "constraint": "size_arg:R3",
                "requires_range": True,
                "writable": True,
            },
            "R3": {"type": "scalar", "constraint": "size"},
            "R4": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "scalar"},
    },
    80: {"name": "bpf_get_current_cgroup_id", "args": {}, "ret": {"type": "scalar"}},
    84: {
        "name": "bpf_sk_lookup_tcp",
        "args": {
            "R1": {"type": "ctx"},
            "R2": {"type": "ptr", "constraint": "tuple_size", "requires_range": True},
            "R3": {"type": "scalar", "constraint": "tuple_size"},
            "R4": {"type": "scalar", "constraint": "netns"},
            "R5": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "sock_or_null"},
    },
    85: {
        "name": "bpf_sk_lookup_udp",
        "args": {
            "R1": {"type": "ctx"},
            "R2": {"type": "ptr", "constraint": "tuple_size", "requires_range": True},
            "R3": {"type": "scalar", "constraint": "tuple_size"},
            "R4": {"type": "scalar", "constraint": "netns"},
            "R5": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "sock_or_null"},
    },
    86: {
        "name": "bpf_sk_release",
        "args": {"R1": {"type": "sock"}},
        "ret": {"type": "scalar"},
    },
    87: {
        "name": "bpf_map_push_elem",
        "args": {
            "R1": {"type": "map_fd"},
            "R2": {"type": "ptr", "constraint": "value_size", "requires_range": True},
            "R3": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "scalar"},
    },
    88: {
        "name": "bpf_map_pop_elem",
        "args": {
            "R1": {"type": "map_fd"},
            "R2": {
                "type": "ptr",
                "constraint": "value_size",
                "requires_range": True,
                "writable": True,
            },
        },
        "ret": {"type": "scalar"},
    },
    89: {
        "name": "bpf_map_peek_elem",
        "args": {
            "R1": {"type": "map_fd"},
            "R2": {
                "type": "ptr",
                "constraint": "value_size",
                "requires_range": True,
                "writable": True,
            },
        },
        "ret": {"type": "scalar"},
    },
    107: {
        "name": "bpf_sk_storage_get",
        "args": {
            "R1": {"type": "map_fd", "constraint": "sk_storage_map"},
            "R2": {"type": "sock"},
            "R3": {
                "type": "ptr",
                "constraint": "value_size",
                "requires_range": True,
                "nullable": True,
            },
            "R4": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "ptr_or_null"},
    },
    108: {
        "name": "bpf_sk_storage_delete",
        "args": {
            "R1": {"type": "map_fd", "constraint": "sk_storage_map"},
            "R2": {"type": "sock"},
        },
        "ret": {"type": "scalar"},
    },
    130: {
        "name": "bpf_ringbuf_output",
        "args": {
            "R1": {"type": "map_fd", "constraint": "ringbuf_map"},
            "R2": {"type": "ptr", "constraint": "size_arg:R3", "requires_range": True},
            "R3": {"type": "scalar", "constraint": "size"},
            "R4": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "scalar"},
    },
    131: {
        "name": "bpf_ringbuf_reserve",
        "args": {
            "R1": {"type": "map_fd", "constraint": "ringbuf_map"},
            "R2": {"type": "scalar", "constraint": "size"},
            "R3": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "ptr_or_null", "to": "ringbuf_mem"},
    },
    132: {
        "name": "bpf_ringbuf_submit",
        "args": {
            "R1": {"type": "ptr", "constraint": "ringbuf_reserved"},
            "R2": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "void"},
    },
    133: {
        "name": "bpf_ringbuf_discard",
        "args": {
            "R1": {"type": "ptr", "constraint": "ringbuf_reserved"},
            "R2": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "void"},
    },
    197: {
        "name": "bpf_dynptr_from_mem",
        "args": {
            "R1": {"type": "ptr", "constraint": "size_arg:R2", "requires_range": True},
            "R2": {"type": "scalar", "constraint": "size"},
            "R3": {"type": "scalar", "constraint": "flags"},
            "R4": {"type": "fp", "constraint": "dynptr_slot", "writable": True},
        },
        "ret": {"type": "scalar"},
    },
    201: {
        "name": "bpf_dynptr_read",
        "args": {
            "R1": {
                "type": "ptr",
                "constraint": "size_arg:R2",
                "requires_range": True,
                "writable": True,
            },
            "R2": {"type": "scalar", "constraint": "len"},
            "R3": {"type": "dynptr"},
            "R4": {"type": "scalar", "constraint": "offset"},
            "R5": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "scalar"},
    },
    202: {
        "name": "bpf_dynptr_write",
        "args": {
            "R1": {"type": "dynptr"},
            "R2": {"type": "scalar", "constraint": "offset"},
            "R3": {"type": "ptr", "constraint": "size_arg:R4", "requires_range": True},
            "R4": {"type": "scalar", "constraint": "len"},
            "R5": {"type": "scalar", "constraint": "flags"},
        },
        "ret": {"type": "scalar"},
    },
}

HELPER_NAME_TO_ID: dict[str, int] = {
    signature["name"]: helper_id for helper_id, signature in HELPER_SIGNATURES.items()
}

_TYPE_LABELS = {
    "ctx": "the verifier-tracked context pointer",
    "dynptr": "a dynptr object",
    "fp": "a stack pointer",
    "map_fd": "a map pointer",
    "ptr": "a valid pointer",
    "scalar": "a scalar value",
    "sock": "a non-null socket pointer",
}
_CONSTRAINT_LABELS = {
    "buf_size": "buf_size",
    "dynptr_slot": "the dynptr stack slot",
    "flags": "helper flags",
    "from_size": "from_size bytes",
    "index": "the program index",
    "key": "the map key",
    "key_size": "key_size bytes",
    "len": "len bytes",
    "netns": "the target netns selector",
    "offset": "the requested offset",
    "perf_event_array": "a perf-event-array map",
    "prog_array": "a prog-array map",
    "ringbuf_map": "a ring-buffer map",
    "ringbuf_reserved": "reserved ring-buffer sample memory",
    "size": "the requested size",
    "size_of_buf": "the output buffer size",
    "sk_storage_map": "an sk-storage map",
    "stack_trace_map": "a stack-trace map",
    "to_size": "to_size bytes",
    "tuple_size": "tuple_size bytes",
    "unsafe_ptr": "the source address",
    "value_size": "value_size bytes",
}


def get_helper_signature(helper_id: int) -> HelperSignature | None:
    """Return the structured signature for a helper ID, if known."""
    return HELPER_SIGNATURES.get(helper_id)


def get_helper_id_by_name(name: str | None) -> int | None:
    """Resolve a helper name like ``bpf_map_lookup_elem`` to its UAPI ID."""
    if not name:
        return None
    normalized = name.strip()
    if not normalized:
        return None
    if not normalized.startswith("bpf_"):
        normalized = f"bpf_{normalized}"
    return HELPER_NAME_TO_ID.get(normalized)


def get_helper_safety_condition(
    helper_id: int,
    error_register: str | None,
) -> "SafetyCondition | None":
    """Return the single helper-argument SafetyCondition for *error_register*."""
    if error_register is None:
        return None
    return _build_helper_condition(helper_id, error_register)


def get_helper_safety_conditions(helper_id: int) -> list["SafetyCondition"]:
    """Return helper-specific argument SafetyConditions for all known args."""
    signature = get_helper_signature(helper_id)
    if signature is None:
        return []
    return [
        condition
        for register in signature.get("args", {})
        if (condition := _build_helper_condition(helper_id, register)) is not None
    ]


def _build_helper_condition(helper_id: int, register: str) -> "SafetyCondition | None":
    signature = get_helper_signature(helper_id)
    if signature is None:
        return None

    arg_spec = (signature.get("args") or {}).get(register)
    if arg_spec is None:
        return None

    from .opcode_safety import SafetyCondition, SafetyDomain

    return SafetyCondition(
        domain=SafetyDomain.ARG_CONTRACT,
        critical_register=register,
        required_property=_describe_arg_contract(arg_spec),
        expected_types=_expected_types(arg_spec),
        allow_null=bool(arg_spec.get("nullable", False)),
        requires_range=bool(arg_spec.get("requires_range", False)),
        requires_writable=bool(arg_spec.get("writable", False)),
        helper_id=helper_id,
        helper_name=signature.get("name"),
        constraint=arg_spec.get("constraint"),
    )


def _expected_types(arg_spec: ArgSpec) -> tuple[str, ...]:
    spec_type = str(arg_spec.get("type", "")).strip().lower()
    mapping = {
        "ctx": ("ctx",),
        "dynptr": ("dynptr",),
        "fp": ("fp",),
        "map_fd": ("map_ptr",),
        "ptr": ("ptr",),
        "scalar": ("scalar",),
        "sock": ("sock",),
    }
    return mapping.get(spec_type, ())


def _describe_arg_contract(arg_spec: ArgSpec) -> str:
    spec_type = str(arg_spec.get("type", "")).strip().lower()
    base = _TYPE_LABELS.get(spec_type, "a verifier-compatible value")

    if spec_type == "ptr" and not bool(arg_spec.get("nullable", False)):
        base = "a non-null pointer"
    if spec_type == "sock":
        base = "a non-null socket pointer returned by a lookup helper"

    modifiers: list[str] = []
    constraint = str(arg_spec.get("constraint", "") or "")
    if bool(arg_spec.get("requires_range", False)):
        range_desc = _CONSTRAINT_LABELS.get(constraint, constraint or "the required bytes")
        modifiers.append(f"with accessible {range_desc}")
    elif constraint:
        modifiers.append(f"matching {_CONSTRAINT_LABELS.get(constraint, constraint)}")

    if bool(arg_spec.get("writable", False)):
        modifiers.append("and writable storage")

    if modifiers:
        return f"must be {base} " + " ".join(modifiers)
    return f"must be {base}"


__all__ = [
    "HELPER_SIGNATURES",
    "HELPER_NAME_TO_ID",
    "get_helper_id_by_name",
    "get_helper_safety_condition",
    "get_helper_safety_conditions",
    "get_helper_signature",
]
