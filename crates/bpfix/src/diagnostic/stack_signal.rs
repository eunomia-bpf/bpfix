use bpfanalysis::helper_abi::{helper_stack_read_pair, helper_writable_stack_output_pair};
use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, initialized_stack_bytes_from_snapshot,
    instruction_uses_register as terminal_instruction_uses_register,
    latest_reg_state_before_instruction, parse_i64_after, stack_read_access, stack_value_range,
    terminal_instruction_contains, terminal_instruction_site, verifier_fragment_start_line,
    verifier_path_snapshot_before_instruction, PathVerifierSnapshot, StackByteRange,
    VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;

use super::{
    call_argument, instruction_is_bpf_exit, is_bare_identifier_argument, rejected_source,
    terminal_fragment_start, ProofSignalContext,
};

pub(super) fn map_lookup_key_argument_unreadable(context: &ProofSignalContext<'_>) -> bool {
    if !context.terminal_error.contains("!read_ok") || context.register != Some(2) {
        return false;
    }
    if !terminal_instruction_contains(
        context.log,
        context.terminal_pc,
        context.terminal_line,
        "call bpf_map_lookup_elem#",
    ) {
        return false;
    }
    let Some(rejected) = rejected_source(context.events) else {
        return false;
    };
    if rejected
        .text
        .match_indices("bpf_map_lookup_elem")
        .take(2)
        .count()
        != 1
    {
        return false;
    }
    call_argument(&rejected.text, "bpf_map_lookup_elem", 1)
        .as_deref()
        .is_some_and(is_bare_identifier_argument)
}

pub(super) fn unreadable_program_entry_argument(context: &ProofSignalContext<'_>) -> bool {
    let Some((reg, instruction, fragment_start)) = unreadable_register_terminal_site(context)
    else {
        return false;
    };
    unreadable_entry_argument(context, instruction, fragment_start, reg)
}

pub(super) fn unreadable_helper_argument(context: &ProofSignalContext<'_>) -> bool {
    let Some((reg, instruction, _)) = unreadable_register_terminal_site(context) else {
        return false;
    };
    unreadable_helper_call_argument(instruction, reg)
}

pub(super) fn unreadable_return_register(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::StackInitialized
        || !context.terminal_error.contains("!read_ok")
        || context.register != Some(0)
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    instruction_is_bpf_exit(instruction.tail)
}

pub(super) fn legacy_skb_load_unreadable_register(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::StackInitialized
        || !context.terminal_error.contains("!read_ok")
        || context.register != Some(6)
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !legacy_skb_load_instruction(instruction.tail) {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(1);
    verifier_path_snapshot_before_instruction(context.branch_states, instruction, fragment_start)
        .is_some_and(|snapshot| !snapshot.regs.contains_key(&6))
}

fn legacy_skb_load_instruction(tail: &str) -> bool {
    let mut tokens = tail.split_whitespace();
    let Some(opcode) = tokens.next() else {
        return false;
    };
    if !matches!(opcode, "(20)" | "(28)" | "(30)" | "(40)" | "(48)" | "(50)") {
        return false;
    }
    let compact: String = tail.split_whitespace().collect();
    compact.contains("=*(u") && compact.contains("*)skb[")
}

fn unreadable_register_terminal_site<'a>(
    context: &'a ProofSignalContext<'a>,
) -> Option<(u8, TerminalInstruction<'a>, usize)> {
    if context.obligation != ProofObligation::StackInitialized
        || !context.terminal_error.contains("!read_ok")
    {
        return None;
    }
    let reg = context.register?;
    if reg == 0 {
        return None;
    }
    let instruction =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)?;
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(1);
    if latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
        .is_some()
    {
        return None;
    }
    Some((reg, instruction, fragment_start))
}

fn unreadable_helper_call_argument(instruction: TerminalInstruction<'_>, reg: u8) -> bool {
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    target == "bpf_skb_store_bytes" && reg == 5
}

pub(super) fn helper_stack_read_exceeds_initialized_range(
    context: &ProofSignalContext<'_>,
) -> bool {
    if context.obligation != ProofObligation::StackInitialized {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("read from stack") || !terminal.contains("memory, len pair") {
        return false;
    }
    let Some(access) = stack_read_access(context.terminal_error) else {
        return false;
    };
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(pair) = helper_stack_read_pair(target) else {
        return false;
    };
    let pointer_reg = pair.ptr_reg;
    let len_reg = pair.len_reg;
    if access.reg != Some(pointer_reg) {
        return false;
    }
    if context.register.is_some_and(|reg| reg != pointer_reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(snapshot) = verifier_path_snapshot_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
    ) else {
        return false;
    };
    let Some(pointer_state) = snapshot.regs.get(&pointer_reg) else {
        return false;
    };
    if pointer_state.reg_type != "fp" {
        return false;
    }
    let pointer_frame = pointer_state.source_frame.unwrap_or(snapshot.frame);
    if pointer_frame != snapshot.frame {
        return false;
    }
    let Some(len) = helper_stack_read_length_from_snapshot(&snapshot, len_reg) else {
        return false;
    };
    if access.size != len || access.delta < 0 {
        return false;
    }
    let Some(start) = pointer_state
        .offset
        .and_then(|offset| i16::try_from(offset).ok())
    else {
        return false;
    };
    if i64::from(start) != access.base_off {
        return false;
    }
    if u64::try_from(access.delta)
        .ok()
        .is_none_or(|delta| delta >= len)
    {
        return false;
    }
    len > u64::try_from(initialized_stack_bytes_from_snapshot(
        &snapshot.stack,
        start,
    ))
    .unwrap_or(0)
}

fn helper_stack_read_length_from_snapshot(
    snapshot: &PathVerifierSnapshot,
    len_reg: u8,
) -> Option<u64> {
    snapshot.regs.get(&len_reg)?.exact_scalar_value()
}

fn unreadable_entry_argument(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: u8,
) -> bool {
    if reg < 2 {
        return false;
    }
    if !terminal_instruction_uses_register(instruction.tail, reg) {
        return false;
    }
    let Some(entry_state) = context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.pc == 0)
        .find(|state| state.regs.get(&1).is_some_and(|reg| reg.reg_type == "ctx"))
    else {
        return false;
    };
    if entry_state.regs.contains_key(&reg) {
        return false;
    }
    context
        .source_events
        .iter()
        .filter(|event| event.log_line >= fragment_start)
        .any(|event| event.pc == Some(0) && looks_like_multi_argument_bpf_entry(&event.source.text))
}

fn looks_like_multi_argument_bpf_entry(text: &str) -> bool {
    let trimmed = text.trim_start();
    let looks_like_function = trimmed.starts_with("int ")
        || trimmed.starts_with("long ")
        || trimmed.contains("BPF_PROG(")
        || trimmed.contains("BPF_KPROBE(");
    looks_like_function && trimmed.contains('(') && trimmed.contains(',')
}

pub(super) fn helper_stack_write_beyond_frame(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::StackInitialized {
        return false;
    }
    let Some(access) = stack_write_access_range(context.terminal_error) else {
        return false;
    };
    if bpf_stack_frame_contains(access) {
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
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(pair) = helper_writable_stack_output_pair(target) else {
        return false;
    };
    let write_reg = pair.ptr_reg;
    let len_reg = pair.len_reg;
    if reg != write_reg {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(1);
    let Some(arg) =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
    else {
        return false;
    };
    if arg.reg_type != "fp" || arg.offset != Some(i32::from(access.start())) {
        return false;
    }
    helper_write_size_argument_matches(context, instruction, fragment_start, len_reg, access)
}

fn helper_write_size_argument_matches(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    len_reg: u8,
    access: StackByteRange,
) -> bool {
    let Some(size_arg) =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, len_reg)
    else {
        return false;
    };
    size_arg.exact_scalar_value() == Some(access.len() as u64)
}

fn stack_write_access_range(message: &str) -> Option<StackByteRange> {
    message
        .to_ascii_lowercase()
        .contains("invalid write to stack")
        .then(|| {
            let offset = parse_i64_after(message, "off=")
                .or_else(|| parse_i64_after(message, "off "))
                .and_then(|value| i16::try_from(value).ok())?;
            let size = parse_i64_after(message, "size=")
                .or_else(|| parse_i64_after(message, "size "))
                .and_then(|value| i16::try_from(value).ok())?;
            stack_value_range(offset, size)
        })
        .flatten()
}

fn bpf_stack_frame_contains(access: StackByteRange) -> bool {
    const BPF_STACK_MIN_OFFSET: i16 = -512;
    BPF_STACK_MIN_OFFSET <= access.start() && access.end() <= 0
}
