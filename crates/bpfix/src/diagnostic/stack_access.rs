use bpfanalysis::verifier_log::{
    latest_reg_state_before_instruction_with_frame, latest_stack_target_overlap_before,
    latest_verifier_state_before_instruction, memory_access_base_register, memory_access_is_load,
    memory_access_is_store, stack_memory_access_range, stack_read_access, RegState, StackByteRange,
    StackReadAccess, StackSlotOverlapQuery, StackState,
    VerifierLogInstruction as TerminalInstruction,
};

use super::{terminal_site, ProofSignalContext};

#[derive(Clone, Copy)]
pub(super) struct StackAccessSite {
    pub(super) range: StackByteRange,
    pub(super) frame: usize,
}

pub(super) fn stack_access_site_from_context(
    context: &ProofSignalContext<'_>,
) -> Option<StackAccessSite> {
    if let Some(access) = stack_read_access(context.terminal_error) {
        return stack_access_site_for_stack_read(context, access);
    }
    terminal_stack_memory_access_site(context)
}

fn stack_access_site_for_stack_read(
    context: &ProofSignalContext<'_>,
    access: StackReadAccess,
) -> Option<StackAccessSite> {
    let range = access.range()?;
    let (instruction, fragment_start) = terminal_site(context)?;
    if let Some(reg) = access.reg {
        if let Some(frame) =
            stack_access_frame_from_register(context, instruction, fragment_start, reg)
        {
            return Some(StackAccessSite { range, frame });
        }
    }
    stack_access_site_for_terminal_range(context, range)
}

pub(super) fn stack_access_site_for_terminal_range(
    context: &ProofSignalContext<'_>,
    range: StackByteRange,
) -> Option<StackAccessSite> {
    let (instruction, fragment_start) = terminal_site(context)?;
    let frame = stack_access_frame_from_instruction(context, instruction, fragment_start)
        .or_else(|| {
            latest_verifier_state_before_instruction(context.states, instruction, fragment_start)
                .map(|state| state.frame)
        })
        .unwrap_or(0);
    Some(StackAccessSite { range, frame })
}

fn stack_access_frame_from_instruction(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> Option<usize> {
    let base_reg = memory_access_base_register(instruction.tail)?;
    stack_access_frame_from_register(context, instruction, fragment_start, base_reg)
}

fn stack_access_frame_from_register(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: u8,
) -> Option<usize> {
    let (base, frame) = latest_reg_state_before_instruction_with_frame(
        context.states,
        instruction,
        fragment_start,
        reg,
    )?;
    (base.reg_type == "fp").then_some(frame)
}

fn terminal_stack_memory_access_site(context: &ProofSignalContext<'_>) -> Option<StackAccessSite> {
    let (instruction, fragment_start) = terminal_site(context)?;
    if !memory_access_is_load(instruction.tail) {
        return None;
    }
    let (range, frame) =
        terminal_stack_memory_range_with_frame(context, instruction, fragment_start)?;
    Some(StackAccessSite { range, frame })
}

pub(super) fn terminal_stack_memory_write_range_with_frame(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> Option<(StackByteRange, usize)> {
    if !memory_access_is_store(instruction.tail) {
        return None;
    }
    terminal_stack_memory_range_with_frame(context, instruction, fragment_start)
}

fn terminal_stack_memory_range_with_frame(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> Option<(StackByteRange, usize)> {
    let base_reg = memory_access_base_register(instruction.tail)?;
    let (base, frame) = latest_reg_state_before_instruction_with_frame(
        context.states,
        instruction,
        fragment_start,
        base_reg,
    )?;
    if base.reg_type != "fp" {
        return None;
    }
    let range = stack_memory_access_range(base, instruction.tail)?;
    Some((range, frame))
}

pub(super) fn latest_stack_value_overlap(
    context: &ProofSignalContext<'_>,
    access: StackAccessSite,
    target_size: i16,
    target_value: impl Fn(&RegState) -> bool,
) -> Option<bool> {
    latest_stack_slot_overlap(context, access, target_size, |stack| {
        stack.value.as_ref().is_some_and(&target_value)
    })
}

fn latest_stack_slot_overlap(
    context: &ProofSignalContext<'_>,
    access: StackAccessSite,
    target_size: i16,
    target_slot: impl Fn(&StackState) -> bool,
) -> Option<bool> {
    let fragment_start = context
        .terminal_line
        .map(|line| bpfanalysis::verifier_log::verifier_fragment_start_line(context.log, line))
        .unwrap_or(0);
    latest_stack_target_overlap_before(
        context.states,
        StackSlotOverlapQuery {
            access: access.range,
            frame: access.frame,
            fragment_start_line: fragment_start,
            before_pc: context.terminal_pc,
            before_line: context.terminal_line,
        },
        target_size,
        |stack, _| target_slot(stack),
    )
}
