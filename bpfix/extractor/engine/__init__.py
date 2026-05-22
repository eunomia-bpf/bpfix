"""Proof engine for eBPF verifier trace analysis.

Public API:
- TraceMonitor: evaluates predicates over instruction traces
- MonitorResult: result of trace monitoring
- OpcodeConditionPredicate: opcode-driven safety condition predicate
- SafetyCondition / SafetyDomain: ISA-derived safety condition structures
- infer_conditions_from_error_insn: opcode-driven condition inference
- find_violated_condition: identify violated condition at error instruction
"""

from __future__ import annotations

from .monitor import (
    CarrierBoundPredicate,
    CarrierLifecycle,
    LifecycleEvent,
    MonitorResult,
    TraceMonitor,
    monitor_carriers,
)
from .opcode_safety import (
    CarrierSpec,
    OpcodeClass,
    OpcodeConditionPredicate,
    OpcodeInfo,
    OperandRole,
    SafetyCondition,
    SafetyDomain,
    SafetySchema,
    decode_opcode,
    discover_compatible_carriers,
    derive_safety_conditions,
    evaluate_condition,
    find_violated_condition,
    infer_conditions_from_error_insn,
    infer_safety_schemas,
    instantiate_primary_carrier,
    instantiate_schema,
    normalize_pointer_kind,
)
from .control_dep import (
    ControlDep,
    compute_control_dependence,
    compute_control_dependence_from_trace,
    controlling_branches,
    control_dependent_instructions,
)
from .slicer import BackwardSlice, backward_slice
from .transition_analyzer import (
    TransitionAnalyzer,
    TransitionChain,
    TransitionDetail,
    TransitionEffect,
    analyze_transitions,
)

__all__ = [
    # Monitor
    "TraceMonitor",
    "MonitorResult",
    "LifecycleEvent",
    "CarrierLifecycle",
    "CarrierBoundPredicate",
    "monitor_carriers",
    # Opcode-driven safety analysis (primary path)
    "OperandRole",
    "SafetySchema",
    "CarrierSpec",
    "OpcodeClass",
    "OpcodeConditionPredicate",
    "OpcodeInfo",
    "SafetyCondition",
    "SafetyDomain",
    "decode_opcode",
    "derive_safety_conditions",
    "evaluate_condition",
    "find_violated_condition",
    "infer_conditions_from_error_insn",
    "infer_safety_schemas",
    "instantiate_primary_carrier",
    "instantiate_schema",
    "discover_compatible_carriers",
    "normalize_pointer_kind",
    # Control dependence
    "ControlDep",
    "compute_control_dependence",
    "compute_control_dependence_from_trace",
    "controlling_branches",
    "control_dependent_instructions",
    # Backward slice (principled data + control dependence)
    "BackwardSlice",
    "backward_slice",
    # Transition analysis
    "TransitionAnalyzer",
    "TransitionChain",
    "TransitionDetail",
    "TransitionEffect",
    "analyze_transitions",
]
