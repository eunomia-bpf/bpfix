use bpfanalysis::verifier_log::{
    latest_reg_state_before_instruction_with_frame, latest_verifier_state_before_instruction,
    memory_access_base_register, memory_access_is_load, memory_access_is_store, stack_access_range,
    stack_value_range, terminal_instruction_access_width, terminal_instruction_memory_offset,
    terminal_instruction_site, verifier_fragment_start_line, RegState, StackByteRange, StackState,
    VerifierLogInstruction as TerminalInstruction,
};

use super::{terminal_fragment_start, ProofSignalContext};

#[derive(Clone, Copy)]
pub(super) struct StackAccessSite {
    pub(super) range: StackByteRange,
    pub(super) frame: usize,
}

pub(super) fn stack_access_site_from_context(
    context: &ProofSignalContext<'_>,
) -> Option<StackAccessSite> {
    if let Some(range) = stack_read_access_range(context.terminal_error) {
        return stack_access_site_for_terminal_range(context, range);
    }
    terminal_stack_memory_access_site(context)
}

pub(super) fn stack_access_site_for_terminal_range(
    context: &ProofSignalContext<'_>,
    range: StackByteRange,
) -> Option<StackAccessSite> {
    let instruction =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)?;
    let fragment_start = terminal_fragment_start(context, instruction);
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
    let (base, frame) = latest_reg_state_before_instruction_with_frame(
        context.states,
        instruction,
        fragment_start,
        base_reg,
    )?;
    (base.reg_type == "fp").then_some(frame)
}

fn stack_read_access_range(message: &str) -> Option<StackByteRange> {
    message
        .to_ascii_lowercase()
        .contains("read from stack")
        .then(|| stack_access_range(message))
        .flatten()
}

fn terminal_stack_memory_access_site(context: &ProofSignalContext<'_>) -> Option<StackAccessSite> {
    let instruction =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)?;
    if !memory_access_is_load(instruction.tail) {
        return None;
    }
    let width =
        terminal_instruction_access_width(context.log, context.terminal_pc, context.terminal_line)?;
    let insn_offset = terminal_instruction_memory_offset(
        context.log,
        context.terminal_pc,
        context.terminal_line,
    )?;
    let base_reg = memory_access_base_register(instruction.tail)?;
    let fragment_start = terminal_fragment_start(context, instruction);
    let (base, frame) = latest_reg_state_before_instruction_with_frame(
        context.states,
        instruction,
        fragment_start,
        base_reg,
    )?;
    if base.reg_type != "fp" {
        return None;
    }
    let base_offset = i64::from(base.offset.unwrap_or(0));
    let start = base_offset.checked_add(insn_offset)?;
    let end = start.checked_add(i64::from(width))?;
    Some(StackAccessSite {
        range: StackByteRange::new(i16::try_from(start).ok()?, i16::try_from(end).ok()?)?,
        frame,
    })
}

pub(super) fn terminal_stack_memory_write_range_with_frame(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> Option<(StackByteRange, usize)> {
    if !memory_access_is_store(instruction.tail) {
        return None;
    }
    let width =
        terminal_instruction_access_width(context.log, context.terminal_pc, context.terminal_line)?;
    let insn_offset = terminal_instruction_memory_offset(
        context.log,
        context.terminal_pc,
        context.terminal_line,
    )?;
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
    let base_offset = i64::from(base.offset.unwrap_or(0));
    let start = base_offset.checked_add(insn_offset)?;
    let end = start.checked_add(i64::from(width))?;
    Some((
        StackByteRange::new(i16::try_from(start).ok()?, i16::try_from(end).ok()?)?,
        frame,
    ))
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
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(0);
    for state in context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.frame == access.frame)
        .filter(|state| context.terminal_pc.is_none_or(|pc| state.pc <= pc))
        .filter(|state| {
            context
                .terminal_line
                .is_none_or(|line| state.log_line < line)
        })
        .rev()
    {
        let mut saw_overlap = false;
        let mut start_in_target = false;
        let mut start_in_non_target = false;
        let mut contains_target = false;
        for (offset, stack) in &state.stack {
            let is_target = target_slot(stack);
            let Some(range) = stack_value_range(*offset, if is_target { target_size } else { 8 })
            else {
                continue;
            };
            if !range.overlaps(access.range) {
                continue;
            }
            saw_overlap = true;
            if range.contains(access.range.start()) {
                if is_target {
                    start_in_target = true;
                } else {
                    start_in_non_target = true;
                }
            }
            if is_target && access.range.contains_range(range) {
                contains_target = true;
            }
        }
        if contains_target || start_in_target {
            return Some(true);
        }
        if start_in_non_target || saw_overlap {
            return Some(false);
        }
    }
    None
}
