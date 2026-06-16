use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, instruction_site_before_line, instructions_in_line_range,
    CallbackKind, VerifierInsn, VerifierLogInstruction as TerminalInstruction,
};

use super::{terminal_site, ProofSignalContext};

pub(super) fn callback_call_while_locked(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("function calls are not allowed") && terminal.contains("holding a lock"))
    {
        return false;
    }
    let Some((terminal_instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    if call_target_from_instruction_tail(terminal_instruction.tail).is_none() {
        return false;
    }
    if !latest_state_is_sync_callback(context, fragment_start, terminal_instruction) {
        return false;
    }
    let Some(callback_entry) =
        latest_sync_callback_entry(context, fragment_start, terminal_instruction)
    else {
        return false;
    };
    let Some(origin_pc) = callback_entry.from_pc else {
        return false;
    };
    let Some(origin_instruction) = instruction_site_before_line(
        context.log,
        origin_pc,
        fragment_start,
        callback_entry.log_line,
    ) else {
        return false;
    };
    let Some(origin_target) = call_target_from_instruction_tail(origin_instruction.tail) else {
        return false;
    };
    if !operation_invokes_verifier_callback(origin_target) {
        return false;
    }
    spin_lock_held_before_instruction(context.log, fragment_start, origin_instruction.line)
}

fn latest_state_is_sync_callback(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    terminal_instruction: TerminalInstruction<'_>,
) -> bool {
    let limit = context
        .terminal_line
        .unwrap_or_else(|| terminal_instruction.line.saturating_add(1));
    context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < limit)
        .filter(|state| state.pc <= terminal_instruction.pc)
        .next_back()
        .is_some_and(|state| state.callback_kind == Some(CallbackKind::Sync))
}

fn latest_sync_callback_entry<'a>(
    context: &'a ProofSignalContext<'_>,
    fragment_start: usize,
    terminal_instruction: TerminalInstruction<'_>,
) -> Option<&'a VerifierInsn> {
    context
        .branch_states
        .iter()
        .filter(|state| state.from_pc.is_some())
        .filter(|state| state.callback_kind == Some(CallbackKind::Sync))
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < terminal_instruction.line)
        .filter(|state| state.pc <= terminal_instruction.pc)
        .next_back()
}

fn operation_invokes_verifier_callback(target: &str) -> bool {
    target.contains("rbtree")
        || matches!(
            target,
            "bpf_loop" | "bpf_for_each_map_elem" | "bpf_user_ringbuf_drain" | "bpf_find_vma"
        )
}

fn spin_lock_held_before_instruction(
    log: &str,
    fragment_start: usize,
    instruction_line: usize,
) -> bool {
    let mut lock_depth = 0u32;
    for instruction in instructions_in_line_range(log, fragment_start, instruction_line) {
        let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
            continue;
        };
        match target {
            "bpf_spin_lock" => lock_depth = lock_depth.saturating_add(1),
            "bpf_spin_unlock" => lock_depth = lock_depth.saturating_sub(1),
            _ => {}
        }
    }
    lock_depth > 0
}
