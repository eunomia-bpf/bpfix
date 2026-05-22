from __future__ import annotations

from dataclasses import dataclass

from bpfix.extractor.engine.helper_signatures import (
    HELPER_SIGNATURES,
    get_helper_id_by_name,
    get_helper_safety_condition,
)
from bpfix.extractor.engine.opcode_safety import (
    SafetyDomain,
    decode_opcode,
    evaluate_condition,
    find_violated_condition,
    infer_conditions_from_error_insn,
)


@dataclass
class MockReg:
    type: str
    off: int | None = None
    range: int | None = None
    umax: int | None = None
    smax: int | None = None


@dataclass
class MockInsn:
    bytecode: str
    pre_state: dict
    post_state: dict
    is_error: bool = True
    error_text: str | None = None
    opcode_hex: str | None = None


def test_helper_table_uses_actual_uapi_ids() -> None:
    assert HELPER_SIGNATURES[1]["name"] == "bpf_map_lookup_elem"
    assert HELPER_SIGNATURES[12]["name"] == "bpf_tail_call"
    assert HELPER_SIGNATURES[35]["name"] == "bpf_get_current_task"
    assert HELPER_SIGNATURES[51]["name"] == "bpf_redirect_map"
    assert HELPER_SIGNATURES[55]["name"] == "bpf_perf_event_read_value"
    assert HELPER_SIGNATURES[80]["name"] == "bpf_get_current_cgroup_id"
    assert HELPER_SIGNATURES[84]["name"] == "bpf_sk_lookup_tcp"
    assert HELPER_SIGNATURES[130]["name"] == "bpf_ringbuf_output"


def test_helper_name_lookup_resolves_real_ids() -> None:
    assert get_helper_id_by_name("bpf_map_lookup_elem") == 1
    assert get_helper_id_by_name("bpf_ringbuf_output") == 130
    assert get_helper_id_by_name("map_lookup_elem") == 1


def test_unknown_helper_returns_none() -> None:
    assert get_helper_safety_condition(999999, "R1") is None


def test_map_update_elem_r1_requires_map_pointer() -> None:
    condition = get_helper_safety_condition(2, "R1")
    assert condition is not None
    assert condition.domain == SafetyDomain.ARG_CONTRACT
    assert evaluate_condition(condition, {"R1": MockReg(type="map_ptr")}) == "satisfied"
    assert evaluate_condition(condition, {"R1": MockReg(type="map_value")}) == "violated"


def test_map_lookup_elem_r2_requires_non_null_pointer() -> None:
    condition = get_helper_safety_condition(1, "R2")
    assert condition is not None
    assert condition.critical_register == "R2"
    assert "key_size" in condition.required_property
    assert evaluate_condition(condition, {"R2": MockReg(type="fp", off=-8)}) == "satisfied"
    assert evaluate_condition(condition, {"R2": MockReg(type="inv")}) == "violated"
    assert evaluate_condition(condition, {"R2": MockReg(type="map_value_or_null", range=8)}) == "violated"


def test_decode_call_extracts_helper_id_from_bytecode() -> None:
    info = decode_opcode("85", "call bpf_sk_lookup_tcp#84")
    assert info.is_call is True
    assert info.helper_id == 84


def test_infer_conditions_from_helper_call_by_name() -> None:
    insn = MockInsn(
        bytecode="call bpf_map_lookup_elem",
        pre_state={
            "R1": MockReg(type="map_ptr"),
            "R2": MockReg(type="inv"),
        },
        post_state={},
        opcode_hex="85",
    )

    conditions = infer_conditions_from_error_insn(insn, error_register="R2")
    assert len(conditions) == 1
    assert conditions[0].domain == SafetyDomain.ARG_CONTRACT
    assert conditions[0].critical_register == "R2"

    violated = find_violated_condition(insn, conditions)
    assert violated is not None
    assert violated.critical_register == "R2"
    assert violated.domain == SafetyDomain.ARG_CONTRACT


def test_infer_conditions_from_helper_call_with_explicit_id() -> None:
    insn = MockInsn(
        bytecode="call bpf_ringbuf_output#130",
        pre_state={
            "R1": MockReg(type="map_ptr"),
            "R2": MockReg(type="map_value", range=16),
            "R3": MockReg(type="scalar", umax=16),
            "R4": MockReg(type="scalar", umax=0),
        },
        post_state={},
        opcode_hex="85",
    )

    conditions = infer_conditions_from_error_insn(insn, error_register="R1")
    assert len(conditions) == 1
    assert conditions[0].helper_id == 130
    assert conditions[0].critical_register == "R1"
    assert evaluate_condition(conditions[0], insn.pre_state) == "satisfied"
