use bpfanalysis::verifier_log::{
    active_validation_start, call_target_from_instruction_tail, instruction_is_bpf_exit,
    instruction_site_before_line, instructions_in_line_range,
    latest_reg_state_in_line_range_before, latest_verifier_state_at_or_before_instruction,
    latest_verifier_state_before, parse_u32_after, scalar_state_outside_required_range,
    terminal_call_target, terminal_required_return_range, validation_seen,
    verifier_fragment_start_line, zero_based_arg_register_after, CallbackKind, RegState,
    VerifierInsn,
};

use crate::family::ProofObligation;

use super::{latest_reg_state_for_call_argument, terminal_site, ProofSignalContext};

pub(super) fn exception_throw_with_live_reference(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    states: &[VerifierInsn],
) -> bool {
    if terminal_call_target(log, terminal_pc, terminal_line) != Some("bpf_throw") {
        return false;
    }
    latest_verifier_state_before(states, terminal_pc, terminal_line).is_some_and(|state| {
        state.callback_kind == Some(CallbackKind::Sync) && state.refs.is_some_and(|refs| refs > 0)
    })
}

pub(super) fn reference_live_at_exit(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::ReferenceLifecycle | ProofObligation::Unknown
    ) {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("unreleased reference id=") {
        return false;
    }
    let Some(ref_id) = parse_u32_after(&terminal, "reference id=") else {
        return false;
    };
    let Some(alloc_pc) =
        parse_u32_after(&terminal, "alloc_insn=").and_then(|pc| usize::try_from(pc).ok())
    else {
        return false;
    };
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    if !instruction_is_bpf_exit(instruction.tail) {
        return false;
    }
    let Some(exit_state) =
        latest_verifier_state_at_or_before_instruction(context.states, instruction, fragment_start)
    else {
        return false;
    };
    exit_state.ref_ids.contains(&ref_id)
        && reference_alloc_call_before_exit(
            context,
            fragment_start,
            instruction.line,
            alloc_pc,
            ref_id,
        )
}

fn reference_alloc_call_before_exit(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    before_line: usize,
    alloc_pc: usize,
    ref_id: u32,
) -> bool {
    let Some(alloc_instruction) =
        instruction_site_before_line(context.log, alloc_pc, fragment_start, before_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(alloc_instruction.tail) else {
        return false;
    };
    reference_acquire_target(target)
        && context
            .states
            .iter()
            .filter(|state| state.log_line >= alloc_instruction.line)
            .filter(|state| state.log_line < before_line)
            .any(|state| state.ref_ids.contains(&ref_id))
}

fn reference_acquire_target(target: &str) -> bool {
    target.contains("_acquire")
        || target.contains("_create")
        || target.ends_with("_new")
        || target.starts_with("bpf_ringbuf_reserve")
        || target == "bpf_kptr_xchg"
        || target == "bpf_obj_new"
}

pub(super) fn exception_callback_protocol_violation(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if terminal.contains("cannot call exception cb directly") {
        return direct_exception_callback_call(context);
    }
    if terminal.contains("at program exit")
        && terminal.contains("register r0")
        && terminal.contains("should have been in")
    {
        return exception_callback_return_contract_mismatch(context);
    }
    false
}

fn direct_exception_callback_call(context: &ProofSignalContext<'_>) -> bool {
    let Some(terminal_line) = context.terminal_line else {
        return false;
    };
    let Some(reported_pc) =
        parse_u32_after(context.terminal_error, "insn ").and_then(|pc| usize::try_from(pc).ok())
    else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, terminal_line);
    let Some(instruction) =
        instruction_site_before_line(context.log, reported_pc, fragment_start, terminal_line)
    else {
        return false;
    };
    if call_target_from_instruction_tail(instruction.tail).is_none() {
        return false;
    }
    validation_seen(context.log, instruction.line, terminal_line)
}

fn exception_callback_return_contract_mismatch(context: &ProofSignalContext<'_>) -> bool {
    let Some(terminal_line) = context.terminal_line else {
        return false;
    };
    let Some(required_range) = terminal_required_return_range(context.terminal_error) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, terminal_line);
    let Some(validation_start) =
        active_validation_start(context.log, fragment_start, terminal_line)
    else {
        return false;
    };
    latest_reg_state_in_line_range_before(
        context.states,
        validation_start,
        terminal_line,
        context.terminal_pc,
        0,
    )
    .is_some_and(|state| scalar_state_outside_required_range(state, required_range))
}

pub(super) fn sleepable_call_in_non_sleepable_context(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("may sleep")
        && !terminal.contains("sleepable helper")
        && !terminal.contains("non-sleepable")
    {
        return false;
    }
    if !terminal.contains("non-sleepable") && !terminal.contains("preempt-disabled") {
        return false;
    }
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    if !instruction.tail.contains("call ") {
        return false;
    }
    prior_non_sleepable_state(context.log, fragment_start, instruction.line)
}

fn prior_non_sleepable_state(log: &str, start_line: usize, before_line: usize) -> bool {
    let mut irq_save_depth = 0u32;
    for instruction in instructions_in_line_range(log, start_line, before_line) {
        let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
            continue;
        };
        match target {
            "bpf_local_irq_save" | "bpf_rcu_read_lock" => {
                irq_save_depth = irq_save_depth.saturating_add(1);
            }
            "bpf_local_irq_restore" | "bpf_rcu_read_unlock" => {
                irq_save_depth = irq_save_depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    irq_save_depth > 0
}

pub(super) fn modern_bpf_object_protocol_violation(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if !modern_bpf_object_protocol_target(target) {
        return false;
    }
    let Some(reg) = modern_bpf_object_protocol_register(&terminal, target, context.register) else {
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

    if terminal.contains("has no valid kptr") {
        return target == "bpf_kptr_xchg" && invalid_kptr_storage_state(state);
    }
    if terminal.contains("must be a rcu pointer") {
        return modern_bpf_object_pointer_state(state)
            && !state.reg_type.starts_with("rcu_ptr")
            && !state.reg_type.starts_with("trusted_ptr");
    }
    if terminal.contains("must be referenced or trusted") {
        return modern_bpf_object_pointer_state(state) && !referenced_or_trusted_state(state);
    }
    if terminal.contains("pointer type struct") && terminal.contains("must point to scalar") {
        return target.starts_with("bpf_cgroup_") && state.reg_type == "fp";
    }
    if terminal.contains("expected pointer to struct") {
        return modern_bpf_object_pointer_state(state);
    }
    if terminal.contains("type=scalar expected=fp")
        || terminal.contains("memory, len pair leads to invalid memory access")
    {
        return target == "bpf_cpumask_populate" && state.reg_type == "scalar";
    }
    false
}

fn modern_bpf_object_protocol_target(target: &str) -> bool {
    target.starts_with("bpf_cgroup_")
        || target.starts_with("bpf_cpumask_")
        || target == "bpf_kptr_xchg"
        || target == "bpf_dynptr_from_skb"
}

fn modern_bpf_object_protocol_register(
    terminal: &str,
    target: &str,
    fallback: Option<u8>,
) -> Option<u8> {
    fallback
        .or_else(|| zero_based_arg_register_after(terminal, "args#"))
        .or_else(|| zero_based_arg_register_after(terminal, "arg#"))
        .or_else(|| {
            (target == "bpf_kptr_xchg" && terminal.contains("has no valid kptr")).then_some(1)
        })
}

fn modern_bpf_object_pointer_state(state: &RegState) -> bool {
    state.reg_type == "fp"
        || state.reg_type == "scalar"
        || state.reg_type.starts_with("ptr_")
        || state.reg_type.starts_with("rcu_ptr")
        || state.reg_type.starts_with("untrusted_ptr")
        || state.reg_type.starts_with("trusted_ptr")
}

fn referenced_or_trusted_state(state: &RegState) -> bool {
    state.reg_type.starts_with("trusted_ptr") || state.reg_type.contains("ref_obj_id")
}

fn invalid_kptr_storage_state(state: &RegState) -> bool {
    state.reg_type == "map_value" || state.reg_type == "fp" || state.reg_type == "scalar"
}
