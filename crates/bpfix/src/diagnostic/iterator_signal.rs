use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, latest_verifier_state_before_instruction, stack_value_range,
    terminal_instruction_site, RegState, VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;

use super::stack_access::{
    latest_stack_value_overlap, stack_access_site_from_context, StackAccessSite,
};
use super::{
    latest_reg_state_for_call_argument_with_frame, terminal_fragment_start, ProofSignalContext,
};

pub(super) fn iterator_stack_storage_access(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::StackInitialized | ProofObligation::Unknown
    ) {
        return false;
    }
    let Some(access) = stack_access_site_from_context(context) else {
        return false;
    };
    latest_stack_value_overlap(context, access, 8, |value| {
        value.reg_type.starts_with("iter_")
    })
    .unwrap_or(false)
}

#[derive(Clone, Copy)]
enum IteratorArg0Requirement {
    EmptyStackSlot,
    LiveIteratorStackSlot,
}

pub(super) fn iterator_helper_argument_state_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::IteratorLifecycle
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
    let Some(requirement) = iterator_arg0_requirement(target) else {
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
        IteratorArg0Requirement::EmptyStackSlot => {
            if arg.reg_type != "fp" {
                return true;
            }
            iterator_stack_slot_state(context, arg, arg_frame).is_some()
        }
        IteratorArg0Requirement::LiveIteratorStackSlot => {
            if arg.reg_type != "fp" {
                return true;
            }
            match iterator_live_stack_slot_state(
                context,
                instruction,
                fragment_start,
                arg,
                arg_frame,
            ) {
                Some(IteratorLiveStackSlotState::LiveIterator) => false,
                Some(IteratorLiveStackSlotState::OrdinaryBytes) => true,
                Some(IteratorLiveStackSlotState::ConsumedIterator) => context
                    .terminal_error
                    .to_ascii_lowercase()
                    .contains("expected an initialized iter"),
                None => false,
            }
        }
    }
}

fn iterator_arg0_requirement(target: &str) -> Option<IteratorArg0Requirement> {
    if !target.starts_with("bpf_iter_") {
        return None;
    }
    if target.ends_with("_new") {
        return Some(IteratorArg0Requirement::EmptyStackSlot);
    }
    if target.ends_with("_next") || target.ends_with("_destroy") {
        return Some(IteratorArg0Requirement::LiveIteratorStackSlot);
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IteratorStackSlotState {
    LiveIterator,
    OrdinaryBytes,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IteratorLiveStackSlotState {
    LiveIterator,
    ConsumedIterator,
    OrdinaryBytes,
}

fn iterator_stack_slot_state(
    context: &ProofSignalContext<'_>,
    arg: &RegState,
    arg_frame: usize,
) -> Option<IteratorStackSlotState> {
    let offset = i16::try_from(arg.offset?).ok()?;
    let range = stack_value_range(offset, 8)?;
    latest_stack_value_overlap(
        context,
        StackAccessSite {
            range,
            frame: arg_frame,
        },
        8,
        |value| value.reg_type.starts_with("iter_"),
    )
    .map(|has_iterator| {
        if has_iterator {
            IteratorStackSlotState::LiveIterator
        } else {
            IteratorStackSlotState::OrdinaryBytes
        }
    })
}

fn iterator_live_stack_slot_state(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    arg: &RegState,
    arg_frame: usize,
) -> Option<IteratorLiveStackSlotState> {
    let offset = i16::try_from(arg.offset?).ok()?;
    let access = stack_value_range(offset, 8)?;
    let current_state =
        latest_verifier_state_before_instruction(context.states, instruction, fragment_start);
    for state in context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .filter(|state| state.frame == arg_frame)
        .rev()
    {
        let mut saw_overlap = false;
        for (slot_offset, stack) in &state.stack {
            let is_iterator = stack
                .value
                .as_ref()
                .is_some_and(|value| value.reg_type.starts_with("iter_"));
            let Some(range) = stack_value_range(*slot_offset, 8) else {
                continue;
            };
            if !range.overlaps(access) {
                continue;
            }
            saw_overlap = true;
            if !is_iterator {
                continue;
            }
            let live = stack
                .value
                .as_ref()
                .and_then(|value| value.ref_id)
                .is_some_and(|ref_id| {
                    current_state.is_some_and(|state| state.ref_ids.contains(&ref_id))
                });
            return Some(if live {
                IteratorLiveStackSlotState::LiveIterator
            } else {
                IteratorLiveStackSlotState::ConsumedIterator
            });
        }
        if saw_overlap {
            return Some(IteratorLiveStackSlotState::OrdinaryBytes);
        }
    }
    None
}
