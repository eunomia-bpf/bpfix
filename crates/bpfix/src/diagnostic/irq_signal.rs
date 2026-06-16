use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, instruction_on_log_line, instruction_site_before_line,
    latest_ref_state_before_instruction, latest_verifier_state_at_or_before_instruction,
    latest_verifier_state_before_instruction, parse_u32_after, stack_value_range,
    terminal_instruction_site, verifier_fragment_start_line, RegState, StackState,
};

use crate::family::ProofObligation;

use super::{
    latest_reg_state_for_call_argument_with_frame, reg_state_has_variable_offset,
    terminal_call_instruction_site, terminal_fragment_start, ProofSignalContext,
};

#[derive(Clone, Copy)]
enum IrqFlagArg0Requirement {
    EmptyStackSlot,
    LiveIrqFlagSlot,
}

pub(super) fn irq_flag_state_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::LockState
            | ProofObligation::HelperArgument
            | ProofObligation::StackInitialized
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(requirement) = irq_flag_arg0_requirement(target) else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        1,
    ) else {
        return false;
    };
    match requirement {
        IrqFlagArg0Requirement::EmptyStackSlot => {
            if arg.reg_type != "fp" {
                return true;
            }
            irq_flag_stack_slot_state(context, arg, arg_frame).is_some()
        }
        IrqFlagArg0Requirement::LiveIrqFlagSlot => {
            if arg.reg_type != "fp" {
                return true;
            }
            irq_flag_stack_slot_state(context, arg, arg_frame)
                .is_some_and(|state| state == IrqFlagStackSlotState::OrdinaryBytes)
        }
    }
}

fn irq_flag_arg0_requirement(target: &str) -> Option<IrqFlagArg0Requirement> {
    match target {
        "bpf_local_irq_save" => Some(IrqFlagArg0Requirement::EmptyStackSlot),
        "bpf_local_irq_restore" => Some(IrqFlagArg0Requirement::LiveIrqFlagSlot),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IrqFlagStackSlotState {
    LiveIrqFlag,
    OrdinaryBytes,
}

fn irq_flag_stack_slot_state(
    context: &ProofSignalContext<'_>,
    arg: &RegState,
    arg_frame: usize,
) -> Option<IrqFlagStackSlotState> {
    let offset = i16::try_from(arg.offset?).ok()?;
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(0);
    for state in context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.frame == arg_frame)
        .filter(|state| context.terminal_pc.is_none_or(|pc| state.pc <= pc))
        .filter(|state| {
            context
                .terminal_line
                .is_none_or(|line| state.log_line < line)
        })
        .rev()
    {
        if let Some(stack) = state.stack.get(&offset) {
            return Some(if is_irq_flag_stack_slot(stack) {
                IrqFlagStackSlotState::LiveIrqFlag
            } else {
                IrqFlagStackSlotState::OrdinaryBytes
            });
        }
        if state.stack.iter().any(|(slot_offset, _)| {
            stack_value_range(*slot_offset, 8).is_some_and(|range| range.contains(offset))
        }) {
            return Some(IrqFlagStackSlotState::OrdinaryBytes);
        }
    }
    None
}

fn is_irq_flag_stack_slot(stack: &StackState) -> bool {
    stack.value.is_none() && stack.slot_types.as_deref() == Some("ffffffff")
}

pub(super) fn irq_restore_order_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::LockState
            | ProofObligation::KfuncReference
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::HelperArgument
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("cannot restore irq state out of order") {
        return false;
    }
    let Some(expected_ref_id) = parse_u32_after(&terminal, "expected id=") else {
        return false;
    };
    let Some(acquired_pc) =
        parse_u32_after(&terminal, "acquired at insn_idx=").and_then(|pc| usize::try_from(pc).ok())
    else {
        return false;
    };
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(flag_arg) = irq_restore_flag_argument(target) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some(acquired_instruction) =
        instruction_site_before_line(context.log, acquired_pc, fragment_start, instruction.line)
    else {
        return false;
    };
    let Some(acquired_target) = call_target_from_instruction_tail(acquired_instruction.tail) else {
        return false;
    };
    if !irq_save_target(acquired_target) {
        return false;
    }
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        flag_arg,
    ) else {
        return false;
    };
    if arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
        return false;
    }
    if irq_flag_stack_slot_state(context, arg, arg_frame)
        != Some(IrqFlagStackSlotState::LiveIrqFlag)
    {
        return false;
    }
    if target == "bpf_local_irq_restore" {
        return latest_ref_state_before_instruction(context.states, instruction, fragment_start)
            .is_some_and(|state| state.ref_ids.contains(&expected_ref_id));
    }
    target == "bpf_res_spin_unlock_irqrestore" && acquired_target == "bpf_res_spin_lock_irqsave"
}

fn irq_restore_flag_argument(target: &str) -> Option<u8> {
    match target {
        "bpf_local_irq_restore" => Some(1),
        "bpf_res_spin_unlock_irqrestore" => Some(2),
        _ => None,
    }
}

fn irq_save_target(target: &str) -> bool {
    matches!(target, "bpf_local_irq_save" | "bpf_res_spin_lock_irqsave")
}

pub(super) fn irq_restore_helper_class_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::LockState
            | ProofObligation::KfuncReference
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::HelperArgument
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("function calls are not allowed") && terminal.contains("holding a lock"))
    {
        return false;
    }
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(restore_target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(flag_arg) = irq_restore_flag_argument(restore_target) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        flag_arg,
    ) else {
        return false;
    };
    if arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
        return false;
    }
    if irq_flag_stack_slot_state(context, arg, arg_frame)
        != Some(IrqFlagStackSlotState::LiveIrqFlag)
    {
        return false;
    }
    let Some(ref_state) =
        latest_verifier_state_before_instruction(context.states, instruction, fragment_start)
    else {
        return false;
    };
    let Some(newest_ref) = ref_state.ref_ids.last().copied() else {
        return false;
    };
    let Some(origin_target) = irq_ref_origin_for_stack_slot(
        context,
        fragment_start,
        instruction.line,
        newest_ref,
        arg,
        arg_frame,
    ) else {
        return false;
    };
    matches!(
        (restore_target, origin_target),
        ("bpf_local_irq_restore", "bpf_res_spin_lock_irqsave")
            | ("bpf_res_spin_unlock_irqrestore", "bpf_local_irq_save")
    )
}

fn irq_ref_origin_for_stack_slot<'a>(
    context: &'a ProofSignalContext<'_>,
    fragment_start: usize,
    before_line: usize,
    ref_id: u32,
    arg: &RegState,
    arg_frame: usize,
) -> Option<&'a str> {
    let offset = i16::try_from(arg.offset?).ok()?;
    context
        .states
        .iter()
        .rev()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.ref_ids.contains(&ref_id))
        .find_map(|state| {
            let target = call_target_on_log_line(context.log, state.log_line)?;
            if !irq_save_target(target) {
                return None;
            }
            if state.frame == arg_frame
                && state.stack.get(&offset).is_some_and(is_irq_flag_stack_slot)
            {
                return Some(target);
            }
            (irq_ref_stack_slot_linked_after_origin(
                context,
                fragment_start,
                state.log_line,
                before_line,
                ref_id,
                offset,
                arg_frame,
            ))
            .then_some(target)
        })
}

fn irq_ref_stack_slot_linked_after_origin(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    origin_line: usize,
    before_line: usize,
    ref_id: u32,
    offset: i16,
    frame: usize,
) -> bool {
    if irq_stack_slot_live_before_line(context, fragment_start, origin_line, offset, frame) {
        return false;
    }
    context
        .states
        .iter()
        .filter(|state| state.log_line > origin_line)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.frame == frame)
        .filter(|state| state.ref_ids.contains(&ref_id))
        .any(|state| state.stack.get(&offset).is_some_and(is_irq_flag_stack_slot))
}

fn irq_stack_slot_live_before_line(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    before_line: usize,
    offset: i16,
    frame: usize,
) -> bool {
    context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.frame == frame)
        .rev()
        .find_map(|state| state.stack.get(&offset))
        .is_some_and(is_irq_flag_stack_slot)
}

pub(super) fn irq_state_live_at_exit(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::LockState
            | ProofObligation::KfuncReference
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("bpf_exit instruction") && terminal.contains("bpf_local_irq_save-ed")) {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !instruction.tail.contains("exit") {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some(exit_state) =
        latest_verifier_state_at_or_before_instruction(context.states, instruction, fragment_start)
    else {
        return false;
    };
    exit_state.ref_ids.iter().any(|ref_id| {
        irq_save_ref_origin_before_exit(context, fragment_start, instruction.line, *ref_id)
    })
}

fn irq_save_ref_origin_before_exit(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    before_line: usize,
    ref_id: u32,
) -> bool {
    context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.ref_ids.contains(&ref_id))
        .any(|state| {
            call_target_on_log_line(context.log, state.log_line).is_some_and(irq_save_target)
        })
}

fn call_target_on_log_line(log: &str, line_number: usize) -> Option<&str> {
    instruction_on_log_line(log, line_number)
        .and_then(|instruction| call_target_from_instruction_tail(instruction.tail))
}
