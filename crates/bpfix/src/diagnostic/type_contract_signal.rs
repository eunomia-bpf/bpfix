use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, direct_call_target_from_instruction_tail,
    latest_reg_state_before_instruction_with_log_line, latest_verifier_state_before_instruction,
    register_written_between, zero_based_arg_register_after, RegState,
    VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;

use super::{
    latest_reg_state_for_call_argument, register_from_terminal_error, terminal_site,
    ProofSignalContext,
};

pub(super) fn kfunc_argument_type_mismatch(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !kfunc_argument_type_terminal(&terminal) {
        return false;
    }
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if !kfunc_object_contract_target(target, &terminal) {
        return false;
    }
    let Some(reg) = context
        .register
        .or_else(|| zero_based_arg_register_after(context.terminal_error, "arg#"))
    else {
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
    if terminal.contains("must be a rcu pointer") {
        if state.reg_type.starts_with("untrusted_ptr") {
            return false;
        }
        return !state.reg_type.starts_with("rcu_ptr")
            && !state.reg_type.starts_with("trusted_ptr");
    }
    if terminal.contains("pointer type struct") && terminal.contains("must point to scalar") {
        return state.reg_type == "fp";
    }
    if let Some(expected) = expected_kfunc_struct_type(&terminal) {
        return !state.reg_type.contains(expected);
    }
    false
}

fn kfunc_argument_type_terminal(terminal: &str) -> bool {
    terminal.contains("must be a rcu pointer")
        || (terminal.contains("pointer type struct") && terminal.contains("must point to scalar"))
        || (terminal.contains("kernel function")
            && terminal.contains("expected pointer to struct")
            && terminal.contains(" but r"))
}

fn kfunc_object_contract_target(target: &str, terminal: &str) -> bool {
    terminal.contains("kernel function")
        || target.contains("cgroup")
        || target.contains("cpumask")
        || target.contains("rbtree")
        || target.contains("kptr")
}

fn expected_kfunc_struct_type(terminal: &str) -> Option<&str> {
    let (_, after) = terminal.split_once("expected pointer to struct ")?;
    after
        .split(|ch: char| ch.is_ascii_whitespace() || ch == ',' || ch == ';')
        .next()
        .filter(|name| !name.is_empty())
}

pub(super) fn verifier_type_contract_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::TypeContract {
        return false;
    }
    let Some((reg, actual_type)) = terminal_type_contract(context.terminal_error) else {
        return false;
    };
    if !(1..=5).contains(&reg) {
        return false;
    }
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    if direct_call_target_from_instruction_tail(instruction.tail).is_none() {
        return false;
    }
    latest_type_contract_argument_state(context, instruction, fragment_start, reg)
        .is_some_and(|state| actual_type_matches_state(&actual_type, state))
}

fn latest_type_contract_argument_state<'a>(
    context: &ProofSignalContext<'a>,
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<&'a RegState> {
    let call_frame =
        latest_verifier_state_before_instruction(context.states, instruction, fragment_start_line)
            .map(|state| state.frame);
    let (state, state_log_line) = latest_reg_state_before_instruction_with_log_line(
        context.states,
        instruction,
        fragment_start_line,
        reg,
    )
    .or_else(|| {
        context
            .states
            .iter()
            .filter(|state| state.log_line >= fragment_start_line)
            .filter(|state| {
                context
                    .terminal_line
                    .is_none_or(|line| state.log_line < line)
            })
            .filter(|state| state.pc <= instruction.pc)
            .filter(|state| call_frame.is_none_or(|frame| state.frame == frame))
            .rev()
            .find_map(|state| {
                let reg_state = state.regs.get(&reg)?;
                Some((reg_state, state.log_line))
            })
    })?;
    (!register_written_between(context.log, state_log_line, instruction.line, reg)).then_some(state)
}

fn terminal_type_contract(message: &str) -> Option<(u8, String)> {
    let reg = register_from_terminal_error(message)?;
    let lower = message.to_ascii_lowercase();
    if lower.contains("trusted arg") {
        return None;
    }
    let (_, after_type) = lower.split_once("type=")?;
    let (actual, after_expected) = after_type.split_once(" expected=")?;
    let actual = actual.trim().trim_end_matches(',');
    let expected = after_expected
        .split(['\n', ';'])
        .next()
        .unwrap_or("")
        .trim();
    if actual.is_empty() || expected.is_empty() || actual.contains("_or_null") {
        return None;
    }
    if actual == "scalar" && expected_type_list_contains(expected, "map_ptr") {
        return None;
    }
    Some((reg, actual.to_string()))
}

fn expected_type_list_contains(expected: &str, needle: &str) -> bool {
    expected
        .split(',')
        .map(str::trim)
        .any(|item| item == needle)
}

fn actual_type_matches_state(actual_type: &str, state: &RegState) -> bool {
    let state_type = state.reg_type.as_str();
    if state_type == actual_type {
        return true;
    }
    match actual_type {
        "scalar" => state_type == "scalar",
        "fp" => state_type == "fp",
        "ctx" => state_type == "ctx",
        "map_ptr" => state_type == "map_ptr",
        "map_value" => state_type == "map_value",
        "mem" => state_type == "mem",
        "ringbuf_mem" => state_type == "ringbuf_mem",
        "ptr_" => state_type.starts_with("ptr_"),
        "trusted_ptr_" => state_type.starts_with("trusted_ptr"),
        "rcu_ptr_" => state_type.starts_with("rcu_ptr"),
        "untrusted_ptr_" => state_type.starts_with("untrusted_ptr"),
        _ if actual_type.ends_with('_') => state_type.starts_with(actual_type),
        _ => false,
    }
}
