use bpfanalysis::verifier_log::{
    latest_reg_state_before_instruction, loose_register_operands as register_operands,
    memory_access_base_register, terminal_error_is_invalid_scalar_memory_access,
    terminal_error_is_pointer_arithmetic, terminal_error_is_pointer_arithmetic_or_bitwise,
    terminal_error_mentions_packet_end, RegState,
};

use crate::family::ProofObligation;

use super::{register_from_terminal_error, terminal_site, ProofSignalContext};

pub(super) fn scalar_value_used_as_pointer(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PointerProvenance {
        return false;
    }
    let scalar_mem_access = terminal_error_is_invalid_scalar_memory_access(context.terminal_error);
    let pkt_end_arithmetic = terminal_error_is_pointer_arithmetic(context.terminal_error)
        && terminal_error_mentions_packet_end(context.terminal_error);
    if !scalar_mem_access && !pkt_end_arithmetic {
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
    if scalar_mem_access && memory_access_base_register(instruction.tail) != Some(reg) {
        return false;
    }
    if pkt_end_arithmetic && register_operands(instruction.tail).first().copied() != Some(reg) {
        return false;
    }
    let Some(state) =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
    else {
        return false;
    };
    if scalar_mem_access {
        state.reg_type == "scalar"
    } else {
        state.reg_type == "pkt_end"
    }
}

pub(super) fn prohibited_pointer_arithmetic(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PointerProvenance {
        return false;
    }
    if !terminal_error_is_pointer_arithmetic_or_bitwise(context.terminal_error) {
        return false;
    }
    if terminal_error_mentions_packet_end(context.terminal_error) {
        return false;
    }
    let Some(reg) = context.register else {
        return false;
    };
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    if register_operands(instruction.tail).first().copied() != Some(reg) {
        return false;
    }
    latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
        .is_some_and(verifier_pointer_state_for_arithmetic)
}

fn verifier_pointer_state_for_arithmetic(state: &RegState) -> bool {
    state.reg_type != "scalar"
}
