from __future__ import annotations

from bpfix.extractor.engine.cfg_builder import build_cfg
from bpfix.extractor.engine.monitor import monitor_carriers
from bpfix.extractor.engine.opcode_safety import (
    OperandRole,
    SafetyDomain,
    discover_compatible_carriers,
    infer_safety_schemas,
    instantiate_primary_carrier,
)
from bpfix.extractor.pipeline import (
    _override_taxonomy_class,
    classify_atom,
    compute_forward_dominators,
)
from bpfix.extractor.trace_parser import RegisterState, TracedInstruction


def _rs(type_: str, **kwargs) -> RegisterState:
    return RegisterState(type=type_, **kwargs)


def _insn(
    idx: int,
    bytecode: str,
    *,
    opcode_hex: str | None = None,
    pre: dict[str, RegisterState] | None = None,
    post: dict[str, RegisterState] | None = None,
    is_error: bool = False,
) -> TracedInstruction:
    return TracedInstruction(
        insn_idx=idx,
        bytecode=bytecode,
        source_line=None,
        pre_state=dict(pre or {}),
        post_state=dict(post or {}),
        backtrack=None,
        is_error=is_error,
        error_text="reject" if is_error else None,
        opcode_hex=opcode_hex,
    )


def _memory_bounds_schema(error_insn: TracedInstruction):
    schemas = infer_safety_schemas(error_insn)
    for schema in schemas:
        if schema.domain == SafetyDomain.MEMORY_BOUNDS:
            return schema
    raise AssertionError("expected a memory-bounds schema")


def test_carrier_discovery_same_provenance():
    error_insn = _insn(
        10,
        "r6 = *(u8 *)(r0 +0)",
        opcode_hex="71",
        pre={
            "R0": _rs("pkt", id=22, off=90, range=0),
            "R5": _rs("pkt", id=22, off=94, range=0),
        },
        is_error=True,
    )

    schema = _memory_bounds_schema(error_insn)
    primary = instantiate_primary_carrier(schema, error_insn)
    carriers = discover_compatible_carriers(schema, primary, error_insn.pre_state)

    assert [carrier.register for carrier in carriers] == ["R0", "R5"]


def test_carrier_discovery_different_provenance():
    error_insn = _insn(
        10,
        "r6 = *(u8 *)(r0 +0)",
        opcode_hex="71",
        pre={
            "R0": _rs("pkt", id=22, off=90, range=0),
            "R5": _rs("pkt", id=7, off=94, range=0),
        },
        is_error=True,
    )

    schema = _memory_bounds_schema(error_insn)
    primary = instantiate_primary_carrier(schema, error_insn)
    carriers = discover_compatible_carriers(schema, primary, error_insn.pre_state)

    assert [carrier.register for carrier in carriers] == ["R0"]


def test_carrier_discovery_different_type():
    error_insn = _insn(
        10,
        "r6 = *(u8 *)(r0 +0)",
        opcode_hex="71",
        pre={
            "R0": _rs("pkt", id=22, off=90, range=0),
            "R5": _rs("map_value", id=22, off=94, range=0),
        },
        is_error=True,
    )

    schema = _memory_bounds_schema(error_insn)
    primary = instantiate_primary_carrier(schema, error_insn)
    carriers = discover_compatible_carriers(schema, primary, error_insn.pre_state)

    assert [carrier.register for carrier in carriers] == ["R0"]


def test_counterexample_a_unrelated_proof():
    instructions = [
        _insn(
            0,
            "r3 = r1",
            opcode_hex="bf",
            post={"R3": _rs("pkt", id=3, off=20, range=0)},
        ),
        _insn(
            1,
            "r3 += r2",
            opcode_hex="0f",
            pre={
                "R3": _rs("pkt", id=3, off=20, range=0),
                "R5": _rs("pkt", id=7, off=20, range=0),
            },
            post={
                "R3": _rs("pkt", id=3, off=20, range=32),
                "R5": _rs("pkt", id=7, off=20, range=0),
            },
        ),
        _insn(
            2,
            "r0 = *(u8 *)(r5 +0)",
            opcode_hex="71",
            pre={
                "R3": _rs("pkt", id=3, off=20, range=32),
                "R5": _rs("pkt", id=7, off=20, range=0),
            },
            is_error=True,
        ),
    ]

    error_insn = instructions[-1]
    schema = _memory_bounds_schema(error_insn)
    cfg = build_cfg(instructions)
    dominators = compute_forward_dominators(cfg)
    result = classify_atom(schema, error_insn, instructions, cfg, dominators)

    assert result.classification == "source_bug"


def test_counterexample_e_vacuous():
    instructions = [
        _insn(
            0,
            "r0 = r1",
            opcode_hex="bf",
            post={"R0": _rs("pkt", id=1, off=0, range=8)},
        ),
        _insn(
            1,
            "r6 = *(u8 *)(r0 +0)",
            opcode_hex="71",
            pre={"R0": _rs("pkt", id=1, off=0, range=8)},
            is_error=True,
        ),
    ]

    error_insn = instructions[-1]
    schema = _memory_bounds_schema(error_insn)
    primary = instantiate_primary_carrier(schema, error_insn)
    lifecycles = monitor_carriers(schema, [primary], instructions)
    lifecycle = lifecycles["R0"]

    assert lifecycle.proof_status == "never_established"
    assert lifecycle.establish_site is None
    assert lifecycle.first_observed_gap == 0
    assert lifecycle.events == []


def test_counterexample_e_vacuous_loss_on_chain_classifies_established_then_lost():
    instructions = [
        _insn(
            0,
            "r0 = r1",
            opcode_hex="bf",
            post={"R0": _rs("pkt", id=1, off=0, range=8)},
        ),
        _insn(
            1,
            "r0 += r2",
            opcode_hex="0f",
            pre={"R0": _rs("pkt", id=1, off=0, range=8)},
            post={"R0": _rs("pkt", id=1, off=8, range=8)},
        ),
        _insn(
            2,
            "r6 = *(u8 *)(r0 +0)",
            opcode_hex="71",
            pre={"R0": _rs("pkt", id=1, off=8, range=8)},
            is_error=True,
        ),
    ]

    error_insn = instructions[-1]
    schema = _memory_bounds_schema(error_insn)
    cfg = build_cfg(instructions)
    dominators = compute_forward_dominators(cfg)
    result = classify_atom(schema, error_insn, instructions, cfg, dominators)

    assert result.classification == "established_then_lost"
    assert result.reason == "vacuous_establishment"
    assert result.loss is not None
    assert result.loss.insn_idx == 1


def test_counterexample_e_vacuous_loss_off_chain_classifies_lowering_artifact():
    instructions = [
        _insn(
            0,
            "r5 = r1",
            opcode_hex="bf",
            post={"R5": _rs("pkt", id=1, off=0, range=8)},
        ),
        _insn(
            1,
            "r5 += r2",
            opcode_hex="0f",
            pre={"R5": _rs("pkt", id=1, off=0, range=8)},
            post={"R5": _rs("pkt", id=1, off=8, range=8)},
        ),
        _insn(
            2,
            "r6 = *(u8 *)(r0 +0)",
            opcode_hex="71",
            pre={
                "R0": _rs("pkt", id=1, off=8, range=8),
                "R5": _rs("pkt", id=1, off=8, range=8),
            },
            is_error=True,
        ),
    ]

    error_insn = instructions[-1]
    schema = _memory_bounds_schema(error_insn)
    cfg = build_cfg(instructions)
    dominators = compute_forward_dominators(cfg)
    result = classify_atom(schema, error_insn, instructions, cfg, dominators)

    assert result.classification == "lowering_artifact"
    assert result.reason == "vacuous_establishment"
    assert result.loss is not None
    assert result.loss.insn_idx == 1


def test_cross_analysis_taxonomy_override_mapping():
    assert _override_taxonomy_class("source_bug", "established_then_lost") == "lowering_artifact"
    assert _override_taxonomy_class("source_bug", "lowering_artifact") == "lowering_artifact"
    assert _override_taxonomy_class("lowering_artifact", "source_bug") == "source_bug"
    assert _override_taxonomy_class("source_bug", "ambiguous") == "source_bug"


def test_schema_inference_ldx():
    error_insn = _insn(
        10,
        "r6 = *(u8 *)(r0 +0)",
        opcode_hex="71",
        pre={"R0": _rs("pkt", id=22, off=90, range=0)},
        is_error=True,
    )

    schemas = infer_safety_schemas(error_insn)

    assert {(schema.domain, schema.role) for schema in schemas} == {
        (SafetyDomain.POINTER_TYPE, OperandRole.BASE_PTR),
        (SafetyDomain.NULL_SAFETY, OperandRole.BASE_PTR),
        (SafetyDomain.MEMORY_BOUNDS, OperandRole.BASE_PTR),
    }


def test_schema_inference_call():
    call_insn = _insn(
        3,
        "call bpf_map_lookup_elem#1",
        opcode_hex="85",
        pre={
            "R1": _rs("map_ptr"),
            "R2": _rs("fp", off=0, range=8),
        },
    )

    schemas = infer_safety_schemas(call_insn)

    assert all(schema.domain == SafetyDomain.ARG_CONTRACT for schema in schemas)
    assert all(schema.role == OperandRole.HELPER_ARG for schema in schemas)
    assert {schema.helper_arg_index for schema in schemas} == {1, 2}


def test_basic_source_bug():
    instructions = [
        _insn(
            0,
            "r0 = r1",
            opcode_hex="bf",
            post={"R0": _rs("pkt", id=1, off=0, range=0)},
        ),
        _insn(
            1,
            "r6 = *(u8 *)(r0 +0)",
            opcode_hex="71",
            pre={"R0": _rs("pkt", id=1, off=0, range=0)},
            is_error=True,
        ),
    ]

    error_insn = instructions[-1]
    schema = _memory_bounds_schema(error_insn)
    cfg = build_cfg(instructions)
    dominators = compute_forward_dominators(cfg)
    result = classify_atom(schema, error_insn, instructions, cfg, dominators)

    assert result.classification == "source_bug"


def test_basic_established_then_lost():
    instructions = [
        _insn(
            0,
            "r0 = r1",
            opcode_hex="bf",
            post={"R0": _rs("pkt", id=1, off=0, range=0)},
        ),
        _insn(
            1,
            "r0 += r2",
            opcode_hex="0f",
            pre={"R0": _rs("pkt", id=1, off=0, range=0)},
            post={"R0": _rs("pkt", id=1, off=0, range=4)},
        ),
        _insn(
            2,
            "r6 = *(u8 *)(r0 +0)",
            opcode_hex="71",
            pre={"R0": _rs("pkt", id=1, off=4, range=4)},
            post={"R0": _rs("pkt", id=1, off=4, range=4)},
            is_error=True,
        ),
    ]

    error_insn = instructions[-1]
    schema = _memory_bounds_schema(error_insn)
    cfg = build_cfg(instructions)
    dominators = compute_forward_dominators(cfg)
    result = classify_atom(schema, error_insn, instructions, cfg, dominators)

    assert result.classification == "established_then_lost"
    assert result.establish is not None
    assert result.loss is not None
