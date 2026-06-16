use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, latest_reg_state_before,
    latest_reg_state_before_instruction, memory_access_base_register,
    register_for_zero_based_arg_index, terminal_instruction_contains,
    verifier_path_snapshot_before_instruction, zero_based_arg_index_after,
};

use crate::family::ProofObligation;

use super::source_query::{
    call_argument, first_call_argument, invalid_args_function_name, is_bare_identifier_argument,
    map_argument_has_relocation_proof, rejected_source, source_for_instruction_in_fragment,
};
use super::{terminal_error_has_nearby_prior_line, terminal_site, ProofSignalContext};

pub(super) fn map_pointer_argument_scalar_zero(context: &ProofSignalContext<'_>) -> bool {
    if !context.terminal_error.contains("expected=map_ptr") {
        return false;
    }
    let Some(reg) = context.register else {
        return false;
    };
    if reg != 1 {
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
    if !rejected.text.contains("bpf_map_lookup_elem") {
        return false;
    }
    let Some(map_argument) = first_call_argument(&rejected.text, "bpf_map_lookup_elem") else {
        return false;
    };
    if !map_argument_has_relocation_proof(&map_argument, rejected, context.source_events) {
        return false;
    }
    let Some(state) = latest_reg_state_before(context.states, context.terminal_pc, reg) else {
        return false;
    };
    state.is_exact_zero_scalar()
}

pub(super) fn btf_func_info_missing(context: &ProofSignalContext<'_>) -> bool {
    if !context
        .terminal_error
        .eq_ignore_ascii_case("missing btf func_info")
    {
        return false;
    }
    log_contains_subprogram(context.log) || log_contains_subprogram_relocation(context.log)
}

pub(super) fn subprogram_reference_metadata_missing(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("caller passes invalid args into func") {
        return false;
    }
    let terminal_has_unknown_reference_size = terminal.contains("reference type('unknown")
        && terminal.contains("size cannot be determined");
    if !terminal_has_unknown_reference_size
        && !terminal_error_has_nearby_prior_line(
            context.log,
            context.terminal_error,
            context.terminal_line,
            3,
            |line| {
                let lower = line.to_ascii_lowercase();
                lower.contains("reference type('unknown")
                    && lower.contains("size cannot be determined")
            },
        )
    {
        return false;
    }
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    if !instruction.tail.contains("call pc+") {
        return false;
    }
    let Some(callee) = invalid_args_function_name(context.terminal_error) else {
        return false;
    };
    let Some(rejected) = source_for_instruction_in_fragment(
        context.source_events,
        instruction.pc,
        fragment_start,
        instruction.line,
    ) else {
        return false;
    };
    let Some(arg_index) = zero_based_arg_index_after(context.terminal_error, "arg#") else {
        return false;
    };
    let Some(argument) = call_argument(&rejected.text, callee, arg_index as usize) else {
        return false;
    };
    let Some(arg_reg) = register_for_zero_based_arg_index(arg_index) else {
        return false;
    };
    if source_argument_erases_reference_metadata(&argument) {
        return true;
    }
    is_bare_identifier_argument(&argument)
        && latest_reg_state_before_instruction(context.states, instruction, fragment_start, arg_reg)
            .is_some_and(|state| state.reg_type == "ctx")
}

fn log_contains_subprogram(log: &str) -> bool {
    log.lines()
        .any(|line| line.trim_start().starts_with("func#1 @"))
}

fn log_contains_subprogram_relocation(log: &str) -> bool {
    log.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("points to subprog")
            || lower.contains("added ") && lower.contains("sub-prog")
    })
}

fn source_argument_erases_reference_metadata(argument: &str) -> bool {
    let compact = argument
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    compact.contains("(void*)") || compact == "void*"
}

pub(super) fn map_pointer_raw_access_contract(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::HelperArgument
        || !context
            .terminal_error
            .contains("only read from bpf_array is supported")
    {
        return false;
    }
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    let Some(snapshot) = verifier_path_snapshot_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
    ) else {
        return false;
    };
    snapshot
        .regs
        .get(&base_reg)
        .is_some_and(|state| state.reg_type == "map_ptr")
}

pub(super) fn perf_event_output_packet_access(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::HelperArgument
        || !context
            .terminal_error
            .contains("helper access to the packet is not allowed")
    {
        return false;
    }
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    if call_target_from_instruction_tail(instruction.tail) != Some("bpf_perf_event_output") {
        return false;
    }
    let Some(snapshot) = verifier_path_snapshot_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
    ) else {
        return false;
    };
    let Some(data) = snapshot.regs.get(&4) else {
        return false;
    };
    let Some(size) = snapshot.regs.get(&5) else {
        return false;
    };
    matches!(data.reg_type.as_str(), "pkt" | "pkt_meta") && size.reg_type == "scalar"
}
