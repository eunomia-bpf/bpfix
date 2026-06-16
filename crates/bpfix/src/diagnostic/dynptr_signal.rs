use bpfanalysis::helper_abi::{
    helper_dynptr_initialized_arg, helper_dynptr_initializer_output_arg, helper_dynptr_live_arg,
};
use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, latest_verifier_state_before_instruction, parse_i64_after,
    reg_state_has_variable_offset, stack_value_range, terminal_instruction_site,
    verifier_fragment_start_line, RegState, StackState, VerifierInsn,
    VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;

use super::source_query::rejected_source;
use super::stack_access::{
    latest_stack_value_overlap, stack_access_site_for_terminal_range,
    stack_access_site_from_context, terminal_stack_memory_write_range_with_frame,
};
use super::{
    dynptr_slot_backing_before, dynptr_stack_slot_for_call_argument,
    latest_live_ref_dynptr_stack_overlap_before_instruction, latest_reg_state_for_call_argument,
    latest_reg_state_for_call_argument_with_frame, terminal_call_instruction_site,
    terminal_fragment_start, DynptrBacking, ProofSignalContext,
};

pub(super) fn dynptr_stack_storage_access(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::StackInitialized | ProofObligation::Unknown
    ) {
        return false;
    }
    if rejected_source(context.events).is_some_and(|source| {
        source.text.contains("bpf_dynptr_slice")
            && context.terminal_error.contains("memory, len pair")
    }) {
        return false;
    }
    let Some(access) = stack_access_site_from_context(context) else {
        return false;
    };
    latest_stack_value_overlap(context, access, 16, |value| {
        value.reg_type.starts_with("dynptr")
    })
    .unwrap_or(false)
}

pub(super) fn dynptr_stack_slot_write_overlap(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::DynptrSafety
            | ProofObligation::HelperArgument
            | ProofObligation::StackInitialized
            | ProofObligation::Unknown
    ) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("potential write to dynptr")
    {
        return false;
    }
    let Some(offset) =
        parse_i64_after(context.terminal_error, "off=").and_then(|value| i16::try_from(value).ok())
    else {
        return false;
    };
    let Some(access) = stack_value_range(offset, 1) else {
        return false;
    };
    let Some(access) = stack_access_site_for_terminal_range(context, access) else {
        return false;
    };
    latest_stack_value_overlap(context, access, 16, |value| {
        value.reg_type.starts_with("dynptr")
    })
    .unwrap_or(false)
}

fn dynptr_protocol_signal_obligation(obligation: ProofObligation) -> bool {
    matches!(
        obligation,
        ProofObligation::DynptrSafety
            | ProofObligation::HelperArgument
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::StackInitialized
            | ProofObligation::TypeContract
            | ProofObligation::Unknown
    )
}

pub(super) fn dynptr_uninitialized_argument(context: &ProofSignalContext<'_>) -> bool {
    if !dynptr_protocol_signal_obligation(context.obligation) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("expected an initialized dynptr")
    {
        return false;
    }
    dynptr_initialized_argument_missing(context)
}

pub(super) fn dynptr_referenced_slot_overwrite(context: &ProofSignalContext<'_>) -> bool {
    if !dynptr_protocol_signal_obligation(context.obligation) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("cannot overwrite referenced dynptr")
    {
        return false;
    }
    dynptr_referenced_stack_slot_overwrite(context)
}

pub(super) fn dynptr_readonly_packet_write(context: &ProofSignalContext<'_>) -> bool {
    if !dynptr_protocol_signal_obligation(context.obligation) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("does not allow writes to packet data")
    {
        return false;
    }
    dynptr_packet_rdwr_disallowed(context)
}

fn dynptr_initialized_argument_missing(context: &ProofSignalContext<'_>) -> bool {
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(arg_reg) = helper_dynptr_initialized_arg(target) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        arg_reg,
    ) else {
        return false;
    };
    if !is_stable_dynptr_stack_arg(arg) {
        return false;
    }
    dynptr_stack_slot_relation(context, instruction, fragment_start, arg, arg_frame).is_none()
}

fn dynptr_referenced_stack_slot_overwrite(context: &ProofSignalContext<'_>) -> bool {
    if let Some(instruction) = terminal_call_instruction_site(context) {
        let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
        if dynptr_initializer_overwrites_referenced_slot(context, instruction, fragment_start) {
            return true;
        }
    }
    dynptr_plain_write_overlaps_referenced_slot(context)
}

fn dynptr_initializer_overwrites_referenced_slot(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> bool {
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(arg_reg) = helper_dynptr_initializer_output_arg(target) else {
        return false;
    };
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        arg_reg,
    ) else {
        return false;
    };
    if dynptr_stack_slot_relation(context, instruction, fragment_start, arg, arg_frame)
        != Some(DynptrStackSlotRelation::Exact)
    {
        return false;
    }
    dynptr_slot_has_live_ref_before_instruction(
        context,
        instruction,
        fragment_start,
        arg.offset,
        arg_frame,
    )
}

fn dynptr_plain_write_overlaps_referenced_slot(context: &ProofSignalContext<'_>) -> bool {
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some((access, frame)) =
        terminal_stack_memory_write_range_with_frame(context, instruction, fragment_start)
    else {
        return false;
    };
    latest_live_ref_dynptr_stack_overlap_before_instruction(
        context,
        instruction,
        fragment_start,
        access,
        frame,
    )
    .unwrap_or(false)
}

fn dynptr_packet_rdwr_disallowed(context: &ProofSignalContext<'_>) -> bool {
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if target != "bpf_dynptr_slice_rdwr" {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some(slot) =
        dynptr_stack_slot_for_call_argument(context.branch_states, instruction, fragment_start, 1)
    else {
        return false;
    };
    dynptr_slot_backing_before(context, slot, instruction.line) == Some(DynptrBacking::Packet)
}

pub(super) fn dynptr_helper_argument_state_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::DynptrSafety
            | ProofObligation::HelperArgument
            | ProofObligation::TypeContract
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);

    if dynptr_initializer_output_slot_mismatch(context, instruction, fragment_start, target) {
        return true;
    }
    if dynptr_from_mem_backing_memory_mismatch(context, instruction, fragment_start, target) {
        return true;
    }
    dynptr_live_argument_interior_pointer(context, instruction, fragment_start, target)
}

pub(super) fn dynptr_slice_variable_length(context: &ProofSignalContext<'_>) -> bool {
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if !matches!(target, "bpf_dynptr_slice" | "bpf_dynptr_slice_rdwr") {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some(length) = latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        4,
    ) else {
        return false;
    };
    length.reg_type == "scalar" && length.exact_value.is_none()
}

fn dynptr_initializer_output_slot_mismatch(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
) -> bool {
    let Some(arg_reg) = helper_dynptr_initializer_output_arg(target) else {
        return false;
    };
    let Some(arg) = latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        arg_reg,
    ) else {
        return false;
    };
    !is_stable_dynptr_stack_arg(arg)
}

fn dynptr_from_mem_backing_memory_mismatch(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
) -> bool {
    if target != "bpf_dynptr_from_mem" {
        return false;
    }
    latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        1,
    )
    .is_some_and(|arg| arg.reg_type == "fp")
}

fn dynptr_live_argument_interior_pointer(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
) -> bool {
    let Some(arg_reg) = helper_dynptr_live_arg(target) else {
        return false;
    };
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        arg_reg,
    ) else {
        return false;
    };
    dynptr_stack_slot_relation(context, instruction, fragment_start, arg, arg_frame)
        == Some(DynptrStackSlotRelation::Interior)
}

pub(super) fn dynptr_release_unacquired_reference(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::DynptrSafety
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::HelperArgument
            | ProofObligation::Unknown
    ) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("unacquired reference")
    {
        return false;
    }
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if !matches!(
        target,
        "bpf_ringbuf_discard_dynptr" | "bpf_ringbuf_submit_dynptr"
    ) {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        1,
    ) else {
        return false;
    };
    if dynptr_stack_slot_relation(context, instruction, fragment_start, arg, arg_frame)
        != Some(DynptrStackSlotRelation::Exact)
    {
        return false;
    }
    latest_verifier_state_before_instruction(context.states, instruction, fragment_start)
        .is_some_and(|state| state.refs.unwrap_or(0) == 0)
}

fn dynptr_slot_has_live_ref_before_instruction(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    offset: Option<i32>,
    frame: usize,
) -> bool {
    let Some(offset) = offset.and_then(|offset| i16::try_from(offset).ok()) else {
        return false;
    };
    context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .filter(|state| state.frame == frame)
        .rev()
        .find_map(|state| {
            let stack = state.stack.get(&offset)?;
            Some(dynptr_stack_slot_has_live_ref(stack, state))
        })
        .unwrap_or(false)
}

pub(super) fn dynptr_stack_slot_has_live_ref(stack: &StackState, state: &VerifierInsn) -> bool {
    let Some(value) = stack.value.as_ref() else {
        return false;
    };
    value.reg_type.starts_with("dynptr")
        && value
            .ref_id
            .is_some_and(|ref_id| state.ref_ids.contains(&ref_id))
}

fn is_stable_dynptr_stack_arg(arg: &RegState) -> bool {
    arg.reg_type == "fp"
        && arg.offset.is_some_and(|offset| offset < 0)
        && !reg_state_has_variable_offset(arg)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DynptrStackSlotRelation {
    Exact,
    Interior,
}

fn dynptr_stack_slot_relation(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    arg: &RegState,
    arg_frame: usize,
) -> Option<DynptrStackSlotRelation> {
    if arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
        return None;
    }
    let offset = i16::try_from(arg.offset?).ok()?;
    let access = stack_value_range(offset, 16)?;
    for state in context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .rev()
    {
        let mut saw_overlapping_stack_state = false;
        if state.frame != arg_frame {
            continue;
        }
        for (slot_offset, stack) in &state.stack {
            let is_dynptr = stack
                .value
                .as_ref()
                .is_some_and(|value| value.reg_type.starts_with("dynptr"));
            let Some(slot_range) = stack_value_range(*slot_offset, if is_dynptr { 16 } else { 8 })
            else {
                continue;
            };
            if !slot_range.overlaps(access) {
                continue;
            }
            saw_overlapping_stack_state = true;
            if !is_dynptr {
                continue;
            }
            if *slot_offset == offset {
                return Some(DynptrStackSlotRelation::Exact);
            }
            if slot_range.contains(offset) {
                return Some(DynptrStackSlotRelation::Interior);
            }
        }
        if saw_overlapping_stack_state {
            return None;
        }
    }
    None
}
