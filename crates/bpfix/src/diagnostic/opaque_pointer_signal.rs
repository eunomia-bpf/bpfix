use bpfanalysis::helper_abi::{helper_probe_read_value_pair, helper_stack_output_pair};
use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, instruction_assigns_register,
    instruction_destination_register, instruction_frame, instruction_register_copy_source,
    instructions_in_line_range, latest_reg_state_before_instruction,
    latest_reg_state_before_instruction_with_frame, latest_reg_state_for_call_argument_with_frame,
    memory_access_base_register, memory_access_is_load, memory_access_is_store,
    memory_access_width, stack_memory_access_range, stack_value_range, terminal_instruction_site,
    StackByteRange, VerifierInsn, VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;

use super::{
    latest_reg_state_before_instruction_with_origin, reg_state_has_variable_offset,
    register_from_terminal_error, terminal_fragment_start, ProofSignalContext,
};

pub(super) fn opaque_scalar_pointer_dereference(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PointerProvenance {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid mem access 'scalar'")
        || terminal.contains("invalid mem access 'inv'"))
    {
        return false;
    }
    let Some(reg) = context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
    else {
        return false;
    };
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if memory_access_base_register(instruction.tail) != Some(reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some((state, _, frame)) = latest_reg_state_before_instruction_with_origin(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    ) else {
        return false;
    };
    if state.reg_type != "scalar" {
        return false;
    }
    let Some(stack_load) = latest_stack_pointer_value_load_source(
        context.branch_states,
        context.log,
        instruction,
        fragment_start,
        reg,
        frame,
    ) else {
        return false;
    };
    probe_read_helper_wrote_stack_range(
        context.branch_states,
        context.log,
        fragment_start,
        stack_load.instruction.line,
        stack_load.range,
        stack_load.storage_frame,
    )
}

struct StackPointerValueLoad<'a> {
    instruction: TerminalInstruction<'a>,
    range: StackByteRange,
    storage_frame: usize,
}

fn latest_stack_pointer_value_load_source<'a>(
    states: &[VerifierInsn],
    log: &'a str,
    terminal_instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: u8,
    frame: usize,
) -> Option<StackPointerValueLoad<'a>> {
    latest_stack_pointer_value_load_source_inner(
        states,
        log,
        terminal_instruction.line,
        fragment_start,
        reg,
        frame,
        0,
    )
}

fn latest_stack_pointer_value_load_source_inner<'a>(
    states: &[VerifierInsn],
    log: &'a str,
    before_line: usize,
    fragment_start: usize,
    reg: u8,
    frame: usize,
    depth: usize,
) -> Option<StackPointerValueLoad<'a>> {
    if depth > 8 {
        return None;
    }
    instructions_in_line_range(log, fragment_start, before_line)
        .filter(|instruction| {
            instruction_assigns_register(instruction.tail, reg)
                && instruction_frame(states, *instruction, fragment_start)
                    .is_none_or(|assigned_frame| assigned_frame == frame)
        })
        .last()
        .and_then(|instruction| {
            if memory_access_is_load(instruction.tail)
                && memory_access_width(instruction.tail) == Some(8)
                && instruction_destination_register(instruction.tail) == Some(reg)
            {
                let base_reg = memory_access_base_register(instruction.tail)?;
                let (base, base_frame) = latest_reg_state_before_instruction_with_frame(
                    states,
                    instruction,
                    fragment_start,
                    base_reg,
                )?;
                if base.reg_type != "fp" || reg_state_has_variable_offset(base) {
                    return None;
                }
                return Some(StackPointerValueLoad {
                    instruction,
                    range: stack_memory_access_range(base, instruction.tail)?,
                    storage_frame: base_frame,
                });
            }
            let source = instruction_register_copy_source(instruction.tail, reg)?;
            latest_stack_pointer_value_load_source_inner(
                states,
                log,
                instruction.line,
                fragment_start,
                source,
                frame,
                depth + 1,
            )
        })
}

fn probe_read_helper_wrote_stack_range(
    states: &[VerifierInsn],
    log: &str,
    fragment_start: usize,
    before_line: usize,
    access: StackByteRange,
    frame: usize,
) -> bool {
    latest_stack_range_writer(states, log, fragment_start, before_line, access, frame).is_some_and(
        |writer| {
            matches!(
                writer,
                StackRangeWriter::ProbeReadValue { written } if written.contains_range(access)
            )
        },
    )
}

#[derive(Clone, Copy)]
enum StackRangeWriter {
    ProbeReadValue { written: StackByteRange },
    Other,
}

fn latest_stack_range_writer(
    states: &[VerifierInsn],
    log: &str,
    fragment_start: usize,
    before_line: usize,
    access: StackByteRange,
    frame: usize,
) -> Option<StackRangeWriter> {
    let instructions =
        instructions_in_line_range(log, fragment_start, before_line).collect::<Vec<_>>();
    instructions.iter().rev().copied().find_map(|instruction| {
        if stack_store_overlaps_range(states, instruction, fragment_start, access, frame) {
            return Some(StackRangeWriter::Other);
        }
        let target = call_target_from_instruction_tail(instruction.tail)?;
        if let Some(written) =
            helper_stack_output_range(states, instruction, fragment_start, target, frame)
        {
            if written.overlaps(access) {
                if probe_read_value_helper(target) {
                    return Some(StackRangeWriter::ProbeReadValue { written });
                }
                return Some(StackRangeWriter::Other);
            }
        }
        if helper_stack_argument_starts_at_access(
            states,
            instruction,
            fragment_start,
            access,
            frame,
        ) {
            return Some(StackRangeWriter::Other);
        }
        None
    })
}

fn stack_store_overlaps_range(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    access: StackByteRange,
    frame: usize,
) -> bool {
    if !memory_access_is_store(instruction.tail) {
        return false;
    }
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    let Some((base, base_frame)) = latest_reg_state_before_instruction_with_frame(
        states,
        instruction,
        fragment_start,
        base_reg,
    ) else {
        return false;
    };
    if base_frame != frame || base.reg_type != "fp" || reg_state_has_variable_offset(base) {
        return false;
    }
    stack_memory_access_range(base, instruction.tail)
        .is_some_and(|written| written.overlaps(access))
}

fn helper_stack_output_range(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
    frame: usize,
) -> Option<StackByteRange> {
    let pair = helper_stack_output_pair(target)?;
    let write_reg = pair.ptr_reg;
    let len_reg = pair.len_reg;
    let (arg, arg_frame) = latest_reg_state_for_call_argument_with_frame(
        states,
        instruction,
        fragment_start,
        Some(instruction.line),
        write_reg,
    )?;
    if arg_frame != frame || arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
        return None;
    }
    let len = helper_exact_u64_argument(states, instruction, fragment_start, len_reg)?;
    let len = i16::try_from(len).ok()?;
    let offset = i16::try_from(arg.offset.unwrap_or_default()).ok()?;
    stack_value_range(offset, len)
}

fn probe_read_value_helper(target: &str) -> bool {
    helper_probe_read_value_pair(target).is_some()
}

fn helper_stack_argument_starts_at_access(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    access: StackByteRange,
    frame: usize,
) -> bool {
    call_target_from_instruction_tail(instruction.tail).is_some()
        && (1..=5).any(|reg| {
            let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
                states,
                instruction,
                fragment_start,
                Some(instruction.line),
                reg,
            ) else {
                return false;
            };
            if arg_frame != frame || arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
                return false;
            }
            i16::try_from(arg.offset.unwrap_or_default()) == Ok(access.start())
        })
}

fn helper_exact_u64_argument(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: u8,
) -> Option<u64> {
    latest_reg_state_before_instruction(states, instruction, fragment_start, reg)?
        .exact_scalar_value()
}
