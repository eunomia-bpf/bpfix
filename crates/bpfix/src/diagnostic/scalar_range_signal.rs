use bpfanalysis::helper_abi::helper_consumes_scalar_length_register;
use bpfanalysis::verifier_log::{
    direct_call_target_from_instruction_tail, instruction_reads_register,
    latest_reg_state_at_or_before_instruction, latest_reg_state_before_instruction,
    map_value_range_may_exceed_value_size, memory_access_base_register, memory_access_offset,
    memory_access_width, parse_i64_after, parse_u32_after, scalar_range_has_any_bound,
    scalar_range_max_i64, scalar_range_may_be_negative, scalar_range_may_include_zero,
    scalar_range_min_i64, scalar_range_upper_unbounded_or_too_large, terminal_instruction_site,
    RegState,
};

use crate::family::ProofObligation;

use super::{
    instruction_is_bpf_exit, register_from_terminal_error, scalar_state_outside_required_range,
    terminal_fragment_start, terminal_required_return_range, ProofSignalContext,
};

const MAX_BPF_STACK_DEPTH: i32 = 512;

pub(super) fn memory_object_access_out_of_bounds(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::ScalarRange {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("invalid access to memory") || !terminal.contains("mem_size=") {
        return false;
    }
    let Some(mem_size) = parse_u32_after(context.terminal_error, "mem_size=") else {
        return false;
    };
    let Some(access_offset) = parse_i64_after(context.terminal_error, "off=") else {
        return false;
    };
    let Some(access_size) = parse_u32_after(context.terminal_error, "size=") else {
        return false;
    };
    if !byte_range_out_of_bounds(access_offset, access_size, mem_size) {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if memory_access_width(instruction.tail) != Some(access_size) {
        return false;
    }
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    if context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
        .is_some_and(|reg| reg != base_reg)
    {
        return false;
    }
    let Some(instruction_offset) = memory_access_offset(instruction.tail) else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(base_state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        base_reg,
    ) else {
        return false;
    };
    if !memory_object_state_matches_size(base_state, mem_size) {
        return false;
    }
    let total_offset = i64::from(base_state.offset.unwrap_or(0)).saturating_add(instruction_offset);
    total_offset == access_offset && byte_range_out_of_bounds(total_offset, access_size, mem_size)
}

fn memory_object_state_matches_size(state: &RegState, mem_size: u32) -> bool {
    state.mem_size == Some(mem_size)
        && (state.reg_type == "mem" || state.reg_type.ends_with("_mem"))
}

fn byte_range_out_of_bounds(offset: i64, size: u32, limit: u32) -> bool {
    offset < 0
        || offset
            .checked_add(i64::from(size))
            .is_none_or(|end| end > i64::from(limit))
}

pub(super) fn return_range_out_of_bounds(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::ScalarRange {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("at program exit")
        || !terminal.contains("register r")
        || !terminal.contains("should have been in")
    {
        return false;
    }
    let Some(required_range) = terminal_required_return_range(context.terminal_error) else {
        return false;
    };
    let reg = context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
        .unwrap_or(0);
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !instruction_is_bpf_exit(instruction.tail) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    latest_reg_state_at_or_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    )
    .or_else(|| {
        latest_reg_state_before_instruction(context.branch_states, instruction, fragment_start, reg)
    })
    .is_some_and(|state| scalar_state_outside_required_range(state, required_range))
}

pub(super) fn stack_variable_offset_out_of_bounds(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::ScalarRange {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("unbounded variable-offset") || !terminal.contains("stack") {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(width) = memory_access_width(instruction.tail) else {
        return false;
    };
    let Some(instruction_offset) = memory_access_offset(instruction.tail) else {
        return false;
    };
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    if context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
        .is_some_and(|reg| reg != base_reg)
    {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(base_state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        base_reg,
    ) else {
        return false;
    };
    stack_pointer_access_range_out_of_bounds(base_state, instruction_offset, width)
}

fn stack_pointer_access_range_out_of_bounds(
    state: &RegState,
    instruction_offset: i64,
    width: u32,
) -> bool {
    if state.reg_type != "fp" || (state.tnum.is_none() && !scalar_range_has_any_bound(state)) {
        return false;
    }
    let base_offset = i64::from(state.offset.unwrap_or(0));
    let min_offset = scalar_range_min_i64(state);
    let max_offset = scalar_range_max_i64(state);
    let width = i64::from(width);
    let min_byte = min_offset.and_then(|offset| {
        base_offset
            .checked_add(offset)
            .and_then(|value| value.checked_add(instruction_offset))
    });
    let max_byte_exclusive = max_offset.and_then(|offset| {
        base_offset
            .checked_add(offset)
            .and_then(|value| value.checked_add(instruction_offset))
            .and_then(|value| value.checked_add(width))
    });
    min_byte.is_none_or(|start| start < i64::from(-MAX_BPF_STACK_DEPTH))
        || max_byte_exclusive.is_none_or(|end| end > 0)
}

pub(super) fn scalar_range_unsafe_at_use(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::ScalarRange {
        return false;
    }
    if !scalar_range_terminal_needs_runtime_bound(context.terminal_error) {
        return false;
    }
    let Some(reg) = context.register else {
        return false;
    };
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !instruction_consumes_scalar_register(instruction.tail, reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
        .is_some_and(|state| scalar_range_state_is_unsafe_for_signal(state, context.terminal_error))
}

fn scalar_range_terminal_needs_runtime_bound(terminal_error: &str) -> bool {
    let terminal = terminal_error.to_ascii_lowercase();
    !terminal.contains("program exit")
        && [
            "min value is negative",
            "zero-sized",
            "unbounded variable-offset",
            "unbounded memory access",
            "math between",
            "invalid access to map value",
            "invalid access to memory",
            "pointer be out of bounds",
            "outside of the allowed memory range",
        ]
        .iter()
        .any(|needle| terminal.contains(needle))
}

fn instruction_consumes_scalar_register(instruction_tail: &str, reg: u8) -> bool {
    let opcode_tail = instruction_tail
        .split_once(';')
        .map(|(opcode, _)| opcode)
        .unwrap_or(instruction_tail);
    if let Some(target) = direct_call_target_from_instruction_tail(opcode_tail) {
        return helper_consumes_scalar_length_register(target, reg);
    }
    instruction_reads_register(opcode_tail, reg)
}

fn scalar_range_state_is_unsafe_for_signal(state: &RegState, terminal_error: &str) -> bool {
    let terminal = terminal_error.to_ascii_lowercase();
    if terminal.contains("zero-sized") {
        return scalar_range_may_include_zero(state);
    }
    if let Some(value) = state.exact_value {
        return value > i32::MAX as u64;
    }
    if map_value_range_may_exceed_value_size(state) {
        return true;
    }
    if state.reg_type != "scalar" && !scalar_range_has_any_bound(state) {
        return false;
    }
    scalar_range_may_be_negative(state) || scalar_range_upper_unbounded_or_too_large(state)
}
