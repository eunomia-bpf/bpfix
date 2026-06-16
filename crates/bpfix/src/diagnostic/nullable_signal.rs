use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, instruction_assigns_register,
    instruction_destination_register, instruction_on_log_line, instruction_opcode_body,
    instruction_register_copy_source, instructions_in_line_range, latest_reg_state_before,
    latest_reg_state_before_instruction, latest_reg_state_before_instruction_with_origin,
    loose_register_operands as register_operands, memory_access_base_register, parse_u32_after,
    RegState, VerifierInsn,
};

use crate::family::ProofObligation;

use super::{
    latest_reg_state_for_call_argument, latest_register_assignment, register_from_terminal_error,
    terminal_site, ProofSignalContext,
};

pub(super) fn nullable_pointer_use_without_proof(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::NullablePointer {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("_or_null") || terminal.contains("possibly null pointer")) {
        return false;
    }
    if terminal.contains("trusted arg") {
        return false;
    }
    let helper_arg_terminal = terminal.contains("helper arg");
    let Some(reg) = (if helper_arg_terminal {
        nullable_use_register(&terminal)
    } else {
        nullable_use_register(&terminal).or(context.register)
    }) else {
        return false;
    };
    let state = if let Some((instruction, fragment_start)) = terminal_site(context) {
        if nullable_instruction_register_mismatch(&terminal, instruction.tail, reg) {
            return false;
        }
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
    } else {
        if helper_arg_terminal {
            return false;
        }
        latest_reg_state_before(context.states, context.terminal_pc, reg)
    };
    state.is_some_and(|state| {
        state.reg_type.contains("_or_null") && !is_trusted_nullable_state(state)
    })
}

fn nullable_use_register(terminal: &str) -> Option<u8> {
    parse_u32_after(terminal, "helper arg")
        .and_then(|reg| (1..=5).contains(&reg).then_some(reg as u8))
}

fn nullable_instruction_register_mismatch(terminal: &str, instruction_tail: &str, reg: u8) -> bool {
    if terminal.contains("helper arg") {
        return call_target_from_instruction_tail(instruction_tail).is_none();
    }
    if terminal.contains("invalid mem access") {
        return memory_access_base_register(instruction_tail).is_some_and(|base| base != reg);
    }
    if terminal.contains("pointer arithmetic") {
        return register_operands(instruction_tail).first().copied() != Some(reg);
    }
    false
}

pub(super) fn null_scalar_dereference_after_pointer_proof(
    context: &ProofSignalContext<'_>,
) -> bool {
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
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    if memory_access_base_register(instruction.tail) != Some(reg) {
        return false;
    }
    let Some((state, _, frame)) = latest_reg_state_before_instruction_with_origin(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    ) else {
        return false;
    };
    if !state.is_exact_zero_scalar() {
        return false;
    }
    register_value_originates_from_nullable_zero_return_helper(
        context.branch_states,
        context.log,
        fragment_start,
        instruction.line,
        reg,
        frame,
        0,
    ) || nullable_branch_refined_register_to_zero(
        context.branch_states,
        context.log,
        reg,
        frame,
        fragment_start,
        instruction.line,
    ) || non_null_pointer_overwritten_with_zero_before_use(
        context.branch_states,
        context.log,
        fragment_start,
        instruction.line,
        reg,
        frame,
    )
}

fn register_value_originates_from_nullable_zero_return_helper(
    states: &[VerifierInsn],
    log: &str,
    fragment_start: usize,
    before_line: usize,
    reg: u8,
    frame: usize,
    depth: usize,
) -> bool {
    if depth > 8 {
        return false;
    }
    let Some(instruction) =
        latest_register_assignment(states, log, fragment_start, before_line, reg, frame)
    else {
        return false;
    };
    if reg == 0
        && call_target_from_instruction_tail(instruction.tail)
            .is_some_and(nullable_zero_return_helper)
    {
        return true;
    }
    let Some(source) = instruction_register_copy_source(instruction.tail, reg) else {
        return false;
    };
    register_value_originates_from_nullable_zero_return_helper(
        states,
        log,
        fragment_start,
        instruction.line,
        source,
        frame,
        depth + 1,
    )
}

fn nullable_branch_refined_register_to_zero(
    states: &[VerifierInsn],
    log: &str,
    reg: u8,
    frame: usize,
    fragment_start: usize,
    before_line: usize,
) -> bool {
    states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.frame == frame)
        .rev()
        .filter(|state| {
            state
                .regs
                .get(&reg)
                .is_some_and(|state| state.is_exact_zero_scalar())
        })
        .find_map(|state| {
            let instruction = instruction_on_log_line(log, state.log_line)?;
            conditional_branch_compares_register_with_zero(instruction.tail, reg)
                .then_some((state.log_line, instruction))
        })
        .is_some_and(|(branch_line, branch_instruction)| {
            latest_reg_state_before_instruction_with_origin(
                states,
                branch_instruction,
                fragment_start,
                reg,
            )
            .is_some_and(|(prior, _, prior_frame)| {
                prior_frame == frame
                    && prior.reg_type.contains("_or_null")
                    && !register_reassigned_to_non_zero_between(log, branch_line, before_line, reg)
            })
        })
}

fn non_null_pointer_overwritten_with_zero_before_use(
    states: &[VerifierInsn],
    log: &str,
    fragment_start: usize,
    before_line: usize,
    reg: u8,
    frame: usize,
) -> bool {
    let Some(instruction) =
        latest_register_assignment(states, log, fragment_start, before_line, reg, frame)
    else {
        return false;
    };
    if !instruction_assigns_exact_zero_to_register(instruction.tail, reg) {
        return false;
    }
    latest_reg_state_before_instruction_with_origin(states, instruction, fragment_start, reg)
        .is_some_and(|(prior, _, prior_frame)| {
            prior_frame == frame && reg_state_is_non_null_pointer_for_null_proof(prior)
        })
}

fn conditional_branch_compares_register_with_zero(instruction_tail: &str, reg: u8) -> bool {
    let body = instruction_opcode_body(instruction_tail);
    body.contains(" if ")
        && body.contains(" goto ")
        && body.contains("0x0")
        && register_operands(body).contains(&reg)
}

fn register_reassigned_to_non_zero_between(
    log: &str,
    after_line: usize,
    before_line: usize,
    reg: u8,
) -> bool {
    instructions_in_line_range(log, after_line.saturating_add(1), before_line).any(|instruction| {
        instruction_assigns_register(instruction.tail, reg)
            && !instruction_assigns_exact_zero_to_register(instruction.tail, reg)
    })
}

fn instruction_assigns_exact_zero_to_register(instruction_tail: &str, reg: u8) -> bool {
    if instruction_destination_register(instruction_tail) != Some(reg) {
        return false;
    }
    instruction_assignment_rhs(instruction_tail).is_some_and(|rhs| matches!(rhs, "0" | "0x0"))
}

fn instruction_assignment_rhs(instruction_tail: &str) -> Option<&str> {
    let (_, rest) = instruction_tail.split_once(')')?;
    let (_, rhs) = rest
        .split_once(';')
        .map_or(rest, |(body, _)| body)
        .trim()
        .split_once(" = ")?;
    Some(rhs.trim())
}

fn reg_state_is_non_null_pointer_for_null_proof(state: &RegState) -> bool {
    !state.reg_type.contains("_or_null") && reg_state_is_pointer_like_for_null_proof(state)
}

fn reg_state_is_pointer_like_for_null_proof(state: &RegState) -> bool {
    state.reg_type.contains("_or_null")
        || matches!(
            state.reg_type.as_str(),
            "map_value" | "mem" | "rdonly_mem" | "ringbuf_mem" | "sock" | "tcp_sock"
        )
        || state.reg_type.starts_with("ptr_")
        || state.reg_type.starts_with("rcu_ptr")
}

fn nullable_zero_return_helper(target: &str) -> bool {
    matches!(target, "bpf_iter_num_next" | "71886" | "71889")
        || target.starts_with("bpf_iter_") && target.ends_with("_next")
}

pub(super) fn trusted_nullable_argument(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let fallback_reg = (context.obligation == ProofObligation::Unknown)
        .then(|| nullable_argument_register_from_call_target(target))
        .flatten();
    let Some(reg) = nullable_argument_register(&terminal).or(fallback_reg) else {
        return false;
    };
    let Some(state) = latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        reg,
    ) else {
        return false;
    };
    is_trusted_nullable_state(state)
        && (terminal.contains("trusted arg")
            || state.reg_type.starts_with("rcu_ptr_or_null")
            || target == "bpf_kptr_xchg")
}

fn nullable_argument_register(message: &str) -> Option<u8> {
    // The verifier prints trusted kfunc args as zero-based argN, while helper
    // args are one-based and map directly to R1..R5.
    if let Some(arg) = parse_u32_after(message, "trusted arg") {
        return arg.checked_add(1).and_then(|reg| reg.try_into().ok());
    }
    parse_u32_after(message, "helper arg").and_then(|reg| reg.try_into().ok())
}

fn nullable_argument_register_from_call_target(target: &str) -> Option<u8> {
    match target {
        "bpf_kptr_xchg" => Some(2),
        _ => None,
    }
}

fn is_trusted_nullable_state(state: &RegState) -> bool {
    state.reg_type.starts_with("rcu_ptr_or_null") || state.reg_type.starts_with("ptr_or_null")
}
