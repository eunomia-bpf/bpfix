use bpfanalysis::verifier_log::{
    conditional_branch_registers, direct_call_target_from_instruction_tail,
    instructions_in_line_range, latest_reg_state_before, latest_reg_state_before_instruction,
    memory_access_base_register, memory_access_offset, memory_access_width, parse_i64_after,
    parse_u32_after, terminal_instruction_site, RegState, VerifierInsn,
};

use crate::family::ProofObligation;
use crate::proof::packet_required_range;
use crate::source::looks_like_packet_bounds_check;

use super::{
    looks_like_packet_pointer_derivation, max_numeric_token, rejected_source, same_source_location,
    terminal_fragment_start, ProofEvent, ProofEventEvidence, ProofEventRole, ProofSignal,
    ProofSignalContext,
};

pub(super) fn packet_pointer_proof_lost_after_bounds_check(events: &[ProofEvent]) -> bool {
    events.iter().any(packet_proof_lost_after_bounds_check)
}

fn packet_proof_lost_after_bounds_check(event: &ProofEvent) -> bool {
    event.role == ProofEventRole::ProofLost
        && event.evidence == ProofEventEvidence::VerifierState
        && event.obligation == ProofObligation::PointerProvenance
        && event
            .source
            .as_ref()
            .is_some_and(|source| looks_like_packet_bounds_check(&source.text))
}

pub(super) fn packet_range_proof_lost_before_access(events: &[ProofEvent]) -> bool {
    let has_sufficient_range = events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::VerifierState
            && event.obligation == ProofObligation::PacketBounds
            && event.source.as_ref().is_some_and(|source| {
                looks_like_packet_pointer_derivation(&source.text)
                    || looks_like_packet_bounds_check(&source.text)
            })
    });
    has_sufficient_range
        && events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost
                && event.evidence == ProofEventEvidence::VerifierState
                && event.obligation == ProofObligation::PacketBounds
        })
}

pub(super) fn packet_guard_undercovers_access(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PacketBounds {
        return false;
    }
    let Some(reg) = context.register else {
        return false;
    };
    let Some(current) = latest_reg_state_before(context.states, context.terminal_pc, reg) else {
        return false;
    };
    let has_sufficient_verifier_range = context.events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::VerifierState
            && event.obligation == ProofObligation::PacketBounds
    });
    !has_sufficient_verifier_range
        && context.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost
                && event.evidence == ProofEventEvidence::VerifierState
                && event.obligation == ProofObligation::PacketBounds
                && event
                    .source
                    .as_ref()
                    .is_some_and(|source| looks_like_packet_bounds_check(&source.text))
                && packet_source_guard_is_linked(
                    context.log,
                    context.branch_states,
                    event.pc,
                    current,
                )
        })
}

pub(super) fn packet_access_without_bounds_proof(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PacketBounds {
        return false;
    }
    let Some(reg) = context.register else {
        return false;
    };
    let Some(required) = packet_required_range(context.terminal_error) else {
        return false;
    };
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    )
    .or_else(|| {
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
    }) else {
        return false;
    };
    if state.reg_type != "pkt" {
        return false;
    }
    if !packet_access_instruction_matches_register(
        instruction.tail,
        reg,
        state,
        context.terminal_error,
    ) {
        return false;
    }
    let Some(range) = state.packet_range else {
        return false;
    };
    if parse_u32_after(context.terminal_error, "r=").is_some_and(|reported| reported != range) {
        return false;
    }
    range < required
}

fn packet_access_instruction_matches_register(
    instruction_tail: &str,
    reg: u8,
    state: &RegState,
    terminal_error: &str,
) -> bool {
    match memory_access_base_register(instruction_tail) {
        Some(base) => {
            base == reg
                && packet_memory_access_shape_matches(instruction_tail, state, terminal_error)
        }
        None => direct_call_target_from_instruction_tail(instruction_tail).is_some_and(|target| {
            packet_helper_consumes_packet_arg(target, reg)
                && packet_terminal_offset_matches_state(state, terminal_error, Some(0))
        }),
    }
}

fn packet_memory_access_shape_matches(
    instruction_tail: &str,
    state: &RegState,
    terminal_error: &str,
) -> bool {
    if parse_u32_after(terminal_error, "size=")
        .is_some_and(|size| memory_access_width(instruction_tail) != Some(size))
    {
        return false;
    }
    packet_terminal_offset_matches_state(
        state,
        terminal_error,
        memory_access_offset(instruction_tail),
    )
}

fn packet_terminal_offset_matches_state(
    state: &RegState,
    terminal_error: &str,
    instruction_offset: Option<i64>,
) -> bool {
    if let Some(reported_off) = parse_i64_after(terminal_error, "off=") {
        let Some(instruction_offset) = instruction_offset else {
            return false;
        };
        let state_off = i64::from(state.offset.unwrap_or(0));
        return state_off.saturating_add(instruction_offset) == reported_off;
    }
    true
}

fn packet_helper_consumes_packet_arg(target: &str, reg: u8) -> bool {
    matches!(target, "bpf_csum_diff") && matches!(reg, 1 | 3)
}

pub(super) fn verifier_precision_signal(context: &ProofSignalContext<'_>) -> Option<ProofSignal> {
    if context.obligation != ProofObligation::PacketBounds {
        return None;
    }
    if packet_max_offset_precision_boundary(context) {
        return Some(ProofSignal::PacketMaxOffsetPrecisionBoundary);
    }
    None
}

fn packet_max_offset_precision_boundary(context: &ProofSignalContext<'_>) -> bool {
    let Some(reg) = context.register else {
        return false;
    };
    let Some(state) = latest_reg_state_before(context.states, context.terminal_pc, reg) else {
        return false;
    };
    let Some(required) = packet_required_range(context.terminal_error) else {
        return false;
    };
    state.reg_type == "pkt"
        && state.packet_range == Some(0)
        && packet_offset_range_reaches_precision_boundary(state, required)
        && packet_source_guard_is_relevant(context.events)
        && (packet_source_guard_covers_required_range(
            context.log,
            context.events,
            context.branch_states,
            state,
            required,
        ) || packet_source_guard_covers_relative_packet_range(
            context.log,
            context.events,
            context.branch_states,
            state,
            required,
        ) || has_prior_sufficient_packet_range_for_rejected_source(context.events))
}

fn packet_offset_range_reaches_precision_boundary(state: &RegState, required: u32) -> bool {
    let variable_max = state
        .range
        .umax
        .or_else(|| state.range.smax.and_then(|value| u64::try_from(value).ok()));
    let fixed_offset = state.offset.and_then(|offset| u64::try_from(offset).ok());
    let max_offset = match (fixed_offset, variable_max) {
        (Some(fixed), Some(variable)) => fixed.saturating_add(variable),
        (None, Some(variable)) => variable,
        _ => return false,
    };
    max_offset.saturating_add(u64::from(required)) > 0xffff
}

fn has_prior_sufficient_packet_range_for_rejected_source(events: &[ProofEvent]) -> bool {
    let Some(rejected) = rejected_source(events) else {
        return false;
    };
    events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::VerifierState
            && event.obligation == ProofObligation::PacketBounds
            && event
                .source
                .as_ref()
                .is_some_and(|source| same_source_location(source, rejected))
    })
}

fn packet_source_guard_is_relevant(events: &[ProofEvent]) -> bool {
    events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::SourceComment
            && event.obligation == ProofObligation::PacketBounds
            && event
                .source
                .as_ref()
                .is_some_and(|source| looks_like_packet_bounds_check(&source.text))
    })
}

fn packet_source_guard_covers_required_range(
    log: &str,
    events: &[ProofEvent],
    states: &[VerifierInsn],
    current: &RegState,
    required: u32,
) -> bool {
    events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::SourceComment
            && event.obligation == ProofObligation::PacketBounds
            && event.source.as_ref().is_some_and(|source| {
                looks_like_packet_bounds_check(&source.text)
                    && packet_source_guard_is_linked(log, states, event.pc, current)
                    && max_numeric_token(&source.text).is_some_and(|guarded| guarded >= required)
            })
    })
}

fn packet_source_guard_covers_relative_packet_range(
    log: &str,
    events: &[ProofEvent],
    states: &[VerifierInsn],
    state: &RegState,
    required: u32,
) -> bool {
    let Some(fixed_offset) = state.offset.and_then(|offset| u32::try_from(offset).ok()) else {
        return false;
    };
    let Some(relative_required) = required.checked_sub(fixed_offset) else {
        return false;
    };
    if relative_required == 0 {
        return false;
    }
    events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::SourceComment
            && event.obligation == ProofObligation::PacketBounds
            && event.source.as_ref().is_some_and(|source| {
                looks_like_packet_bounds_check(&source.text)
                    && packet_source_guard_is_linked(log, states, event.pc, state)
                    && packet_source_guard_covers_relative_bound(&source.text, relative_required)
            })
    })
}

fn packet_source_guard_covers_relative_bound(source_text: &str, relative_required: u32) -> bool {
    max_numeric_token(source_text).is_some_and(|guarded| guarded >= relative_required)
        || (relative_required <= 1 && source_text.contains("sizeof("))
}

fn packet_source_guard_is_linked(
    log: &str,
    states: &[VerifierInsn],
    guard_pc: Option<usize>,
    current: &RegState,
) -> bool {
    packet_guard_verifier_state_links_to_rejected(log, states, guard_pc, current)
}

fn packet_guard_verifier_state_links_to_rejected(
    log: &str,
    states: &[VerifierInsn],
    guard_pc: Option<usize>,
    current: &RegState,
) -> bool {
    let Some(guard_pc) = guard_pc else {
        return false;
    };
    guard_branch_packet_operand_registers(log, states, guard_pc, 6)
        .into_iter()
        .any(|(pc, reg)| {
            states
                .iter()
                .filter(|state| state.pc == pc)
                .filter_map(|state| state.regs.get(&reg))
                .any(|state| packet_guard_operand_covers_current(state, current))
        })
}

pub(super) fn guard_branch_packet_operand_registers(
    log: &str,
    states: &[VerifierInsn],
    guard_pc: usize,
    lookahead: usize,
) -> Vec<(usize, u8)> {
    let mut operands = Vec::new();
    for (pc, regs) in guard_branch_register_sets(log, guard_pc, lookahead) {
        for state in states.iter().filter(|state| state.pc == pc) {
            for reg in &regs {
                if branch_operand_is_packet_checked_against_pkt_end(state, &regs, *reg) {
                    operands.push((pc, *reg));
                }
            }
        }
    }
    operands
}

fn branch_operand_is_packet_checked_against_pkt_end(
    state: &VerifierInsn,
    branch_regs: &[u8],
    reg: u8,
) -> bool {
    state
        .regs
        .get(&reg)
        .is_some_and(|reg_state| reg_state.reg_type == "pkt")
        && branch_regs.iter().any(|other| {
            *other != reg
                && state
                    .regs
                    .get(other)
                    .is_some_and(|reg_state| reg_state.reg_type == "pkt_end")
        })
}

fn packet_guard_operand_covers_current(guard: &RegState, current: &RegState) -> bool {
    if guard.reg_type != "pkt" || current.reg_type != "pkt" {
        return false;
    }
    match (guard.id, current.id) {
        (Some(guard_id), Some(current_id)) if guard_id == current_id => {
            packet_offset_covers(guard, current)
        }
        (None, None) => packet_offset_covers(guard, current),
        _ => false,
    }
}

fn packet_offset_covers(guard: &RegState, current: &RegState) -> bool {
    guard.offset.unwrap_or(0) >= current.offset.unwrap_or(0)
}

fn guard_branch_register_sets(
    log: &str,
    guard_pc: usize,
    lookahead: usize,
) -> Vec<(usize, Vec<u8>)> {
    let max_pc = guard_pc.saturating_add(lookahead);
    instructions_in_line_range(log, 1, usize::MAX)
        .filter(|instruction| instruction.pc >= guard_pc && instruction.pc <= max_pc)
        .filter_map(|instruction| {
            let regs = conditional_branch_registers(instruction.tail);
            (!regs.is_empty()).then_some((instruction.pc, regs))
        })
        .collect()
}
