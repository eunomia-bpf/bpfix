use bpfanalysis::helper_abi::helper_dynptr_initializer_output_arg;
use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, instructions_in_line_range, reg_state_has_variable_offset,
    verifier_fragment_start_line, VerifierInsn, VerifierLogInstruction as TerminalInstruction,
};

use super::ProofSignalContext;

pub(super) use bpfanalysis::verifier_log::{
    latest_reg_state_before_instruction_with_origin, latest_reg_state_for_call_argument,
    latest_reg_state_for_call_argument_with_frame, latest_register_assignment,
    reg_state_is_pointer_like as is_pointer_state,
    register_from_verifier_error as register_from_terminal_error,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DynptrStackSlot {
    pub(super) frame: usize,
    pub(super) offset: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DynptrBacking {
    Packet,
    Memory,
}

pub(super) fn terminal_fragment_start(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
) -> usize {
    context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line))
}

pub(super) fn terminal_instruction<'log>(
    context: &ProofSignalContext<'log>,
) -> Option<TerminalInstruction<'log>> {
    bpfanalysis::verifier_log::terminal_instruction_site(
        context.log,
        context.terminal_pc,
        context.terminal_line,
    )
}

pub(super) fn terminal_site<'log>(
    context: &ProofSignalContext<'log>,
) -> Option<(TerminalInstruction<'log>, usize)> {
    let instruction = terminal_instruction(context)?;
    let fragment_start = terminal_fragment_start(context, instruction);
    Some((instruction, fragment_start))
}

pub(super) fn dynptr_slot_backing_before(
    context: &ProofSignalContext<'_>,
    slot: DynptrStackSlot,
    before_line: usize,
) -> Option<DynptrBacking> {
    let fragment_start = verifier_fragment_start_line(context.log, before_line);
    instructions_in_line_range(context.log, fragment_start, before_line)
        .filter_map(|instruction| {
            let target = call_target_from_instruction_tail(instruction.tail)?;
            let backing = dynptr_backing_from_helper(target)?;
            let arg_reg = helper_dynptr_initializer_output_arg(target)?;
            let initialized_slot = dynptr_stack_slot_for_call_argument(
                context.branch_states,
                instruction,
                fragment_start,
                arg_reg,
            )?;
            (initialized_slot == slot).then_some(backing)
        })
        .last()
}

pub(super) fn dynptr_stack_slot_for_call_argument(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<DynptrStackSlot> {
    let (arg, frame) = latest_reg_state_for_call_argument_with_frame(
        states,
        instruction,
        fragment_start_line,
        Some(instruction.line),
        reg,
    )?;
    if arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
        return None;
    }
    Some(DynptrStackSlot {
        frame,
        offset: arg.offset?,
    })
}

fn dynptr_backing_from_helper(target: &str) -> Option<DynptrBacking> {
    match target {
        "bpf_dynptr_from_skb" | "bpf_dynptr_from_xdp" => Some(DynptrBacking::Packet),
        "bpf_dynptr_from_mem" => Some(DynptrBacking::Memory),
        _ => None,
    }
}

pub(super) fn terminal_call_instruction_site<'a>(
    context: &'a ProofSignalContext<'a>,
) -> Option<TerminalInstruction<'a>> {
    bpfanalysis::verifier_log::terminal_or_nearest_call_instruction_site(
        context.log,
        context.terminal_pc,
        context.terminal_line,
        context.terminal_call_target,
    )
}

pub(super) fn terminal_error_has_nearby_prior_line(
    log: &str,
    terminal_error: &str,
    terminal_line: Option<usize>,
    lookback: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let lines = log.lines().collect::<Vec<_>>();
    if let Some((line, idx)) = terminal_line.and_then(|line| Some((line, line.checked_sub(1)?))) {
        let fragment_start = verifier_fragment_start_line(log, line).saturating_sub(1);
        let lookback_start = idx.saturating_sub(lookback).max(fragment_start);
        return lines.get(idx).is_some_and(|line| {
            line.contains(terminal_error)
                && lines[lookback_start..idx]
                    .iter()
                    .any(|prior| predicate(prior))
        });
    }
    lines.iter().enumerate().any(|(idx, line)| {
        line.contains(terminal_error)
            && lines[idx.saturating_sub(lookback)..idx]
                .iter()
                .any(|prior| predicate(prior))
    })
}
