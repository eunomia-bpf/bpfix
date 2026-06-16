use bpfanalysis::verifier_log::{
    latest_nullable_state, latest_pointer_to_scalar_transition, latest_reg_state_index_before,
    latest_unsafe_scalar_state, scalar_range_has_any_bound, scalar_ranges_match,
    verifier_value_summary, RegState, VerifierInsn,
};

use crate::family::ProofObligation;
use crate::proof::packet_required_range;
use crate::source::{
    latest_source_before, looks_like_null_check, looks_like_nullable_return,
    looks_like_packet_bounds_check, looks_like_reference_acquire, looks_like_reference_release,
    looks_like_scalar_guard, looks_like_stack_initialization, source_for_pc, SourceEvent,
    SourceLocation,
};

use super::packet_signal::guard_branch_packet_operand_registers;
use super::source_query::{
    identifier_tokens, looks_like_packet_pointer_derivation, same_source_location,
    source_for_pc_in_rejected_file,
};
use super::{ProofEvent, ProofEventEvidence, ProofEventRole};

pub(super) fn pointer_provenance_events(
    states: &[VerifierInsn],
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(source) = rejected_source {
        if let Some(event) = latest_source_before(source_events, Some(source), |text| {
            text.contains("if (") && !text.contains("data_end")
        }) {
            events.push(ProofEvent {
                role: ProofEventRole::ProofLost,
                evidence: ProofEventEvidence::SourceComment,
                obligation: ProofObligation::PointerProvenance,
                pc: event.pc,
                source: Some(event.source.clone()),
                register,
                detail: "proof can be lost when branch-specific pointers are merged".to_string(),
            });
        }

        if let Some(event) = latest_source_before(source_events, Some(source), |text| {
            text.contains("data_end")
        }) {
            events.push(ProofEvent {
                role: ProofEventRole::ProofEstablished,
                evidence: ProofEventEvidence::SourceComment,
                obligation: ProofObligation::PointerProvenance,
                pc: event.pc,
                source: Some(event.source.clone()),
                register,
                detail: "proof established by a verifier-visible bounds check".to_string(),
            });
        }
    }

    if let Some((pc, kind)) =
        register.and_then(|reg| latest_pointer_to_scalar_transition(states, terminal_pc, reg))
    {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::VerifierState,
            obligation: ProofObligation::PointerProvenance,
            pc: Some(pc),
            source: source_for_pc(source_events, pc).cloned(),
            register,
            detail: format!(
                "verifier state changes from {kind} to scalar before the rejected access"
            ),
        });
    }

    events
}

pub(super) struct PacketBoundsEventContext<'a> {
    pub(super) log: &'a str,
    pub(super) states: &'a [VerifierInsn],
    pub(super) branch_states: &'a [VerifierInsn],
    pub(super) source_events: &'a [SourceEvent],
    pub(super) terminal_pc: Option<usize>,
    pub(super) terminal_error: &'a str,
    pub(super) rejected_source: Option<&'a SourceLocation>,
    pub(super) register: Option<u8>,
}

pub(super) fn packet_bounds_events(context: &PacketBoundsEventContext<'_>) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) =
        latest_source_before(context.source_events, context.rejected_source, |text| {
            looks_like_packet_bounds_check(text)
        })
    {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::PacketBounds,
            pc: event.pc,
            source: Some(event.source.clone()),
            register: context.register,
            detail: "packet bounds proof is established by this data_end check".to_string(),
        });
    }
    if let Some((pc, range, required)) = latest_sufficient_packet_range(
        context.states,
        context.terminal_pc,
        context.terminal_error,
        context.register,
    )
    .or_else(|| latest_sufficient_packet_guard_range(context))
    {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            evidence: ProofEventEvidence::VerifierState,
            obligation: ProofObligation::PacketBounds,
            pc: Some(pc),
            source: source_for_pc(context.source_events, pc).cloned(),
            register: context.register,
            detail: format!(
                "verifier had proved packet range {range} bytes here, enough for the required {required} bytes"
            ),
        });
        if let Some((pc, current_range)) = packet_range_lost_before_access(
            context.states,
            context.terminal_pc,
            context.terminal_error,
            context.register,
            pc,
        ) {
            events.push(ProofEvent {
                role: ProofEventRole::ProofLost,
                evidence: ProofEventEvidence::VerifierState,
                obligation: ProofObligation::PacketBounds,
                pc: Some(pc),
                source: source_for_pc(context.source_events, pc).cloned(),
                register: context.register,
                detail: format!(
                    "verifier packet range for this register dropped to {current_range} bytes before the rejected access"
                ),
            });
        }
    } else if let Some((pc, range, required)) = latest_insufficient_packet_range(
        context.states,
        context.terminal_pc,
        context.terminal_error,
        context.register,
    ) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::VerifierState,
            obligation: ProofObligation::PacketBounds,
            pc: Some(pc),
            source: source_for_pc_in_rejected_file(
                context.source_events,
                pc,
                context.rejected_source,
            ),
            register: context.register,
            detail: format!(
                "verifier only proves packet range {range} bytes on this path, but the rejected access requires {required} bytes"
            ),
        });
    }
    events
}

fn latest_sufficient_packet_range(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    terminal_error: &str,
    register: Option<u8>,
) -> Option<(usize, u32, u32)> {
    let reg = register?;
    let required = packet_required_range(terminal_error)?;
    let (idx, state, reg_state) = latest_reg_state_index_before(states, terminal_pc, reg)?;
    if reg_state.reg_type != "pkt" {
        return None;
    }
    if let Some(range) = reg_state.packet_range {
        if range >= required {
            return Some((state.pc, range, required));
        }
    }
    prior_sufficient_packet_range(states, idx, reg, required, reg_state)
}

fn latest_insufficient_packet_range(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    terminal_error: &str,
    register: Option<u8>,
) -> Option<(usize, u32, u32)> {
    let reg = register?;
    let required = packet_required_range(terminal_error)?;
    // A one-byte access with r=0 is common when no packet proof exists at all.
    // Avoid adding a low-signal related span unless the access needs a wider range.
    if required <= 1 {
        return None;
    }
    let (_, state, reg_state) = latest_reg_state_index_before(states, terminal_pc, reg)?;
    if reg_state.reg_type != "pkt" {
        return None;
    }
    let range = reg_state.packet_range?;
    (range < required).then_some((state.pc, range, required))
}

fn packet_range_lost_before_access(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    terminal_error: &str,
    register: Option<u8>,
    proof_pc: usize,
) -> Option<(usize, u32)> {
    let reg = register?;
    let required = packet_required_range(terminal_error)?;
    if required <= 1 {
        return None;
    }
    let (_, state, reg_state) = latest_reg_state_index_before(states, terminal_pc, reg)?;
    if state.pc <= proof_pc || reg_state.reg_type != "pkt" {
        return None;
    }
    let range = reg_state.packet_range?;
    (range < required).then_some((state.pc, range))
}

fn prior_sufficient_packet_range(
    states: &[VerifierInsn],
    before_idx: usize,
    reg: u8,
    required: u32,
    current: &RegState,
) -> Option<(usize, u32, u32)> {
    for state in states[..before_idx].iter().rev() {
        let Some(reg_state) = state.regs.get(&reg) else {
            continue;
        };
        if reg_state.reg_type != "pkt" {
            return None;
        }
        if !same_packet_lineage(reg_state, current) {
            return None;
        }
        let Some(range) = reg_state.packet_range else {
            continue;
        };
        if range >= required {
            return Some((state.pc, range, required));
        }
    }
    None
}

fn same_packet_lineage(prior: &RegState, current: &RegState) -> bool {
    if prior.reg_type != "pkt" || current.reg_type != "pkt" {
        return false;
    }
    match (prior.id, current.id) {
        (Some(prior_id), Some(current_id)) => prior_id == current_id,
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (None, None) => true,
    }
}

fn latest_sufficient_packet_guard_range(
    context: &PacketBoundsEventContext<'_>,
) -> Option<(usize, u32, u32)> {
    let reg = context.register?;
    let required = packet_required_range(context.terminal_error)?;
    let (current_idx, _, current) =
        latest_reg_state_index_before(context.states, context.terminal_pc, reg)?;
    if current.reg_type != "pkt" || current.packet_range.is_some_and(|range| range >= required) {
        return None;
    }
    let rejected = context.rejected_source?;
    context
        .source_events
        .iter()
        .filter(|event| event.source.path == rejected.path)
        .filter(|event| event.source.line < rejected.line)
        .filter(|event| looks_like_packet_bounds_check(&event.source.text))
        .filter_map(|event| {
            let guard_pc = event.pc?;
            if context.terminal_pc.is_some_and(|pc| guard_pc > pc) {
                return None;
            }
            let mixed_id_same_register_history =
                has_prior_noid_same_register_packet_range_for_guard(
                    context.states,
                    context.source_events,
                    current_idx,
                    reg,
                    required,
                    current,
                    &event.source,
                );
            Some((guard_pc, mixed_id_same_register_history))
        })
        .flat_map(|(guard_pc, mixed_id_same_register_history)| {
            guard_branch_packet_operand_registers(context.log, context.branch_states, guard_pc, 6)
                .into_iter()
                .map(move |operand| (guard_pc, mixed_id_same_register_history, operand))
        })
        .filter_map(
            |(guard_source_pc, mixed_id_same_register_history, (branch_pc, branch_reg))| {
                context
                    .branch_states
                    .iter()
                    .filter(|state| state.pc == branch_pc)
                    .filter_map(|state| state.regs.get(&branch_reg))
                    .find_map(|guard| {
                        packet_guard_proves_rejected_access(
                            guard,
                            current,
                            required,
                            mixed_id_same_register_history,
                        )
                        .map(|range| (guard_source_pc, range, required))
                    })
            },
        )
        .max_by_key(|(pc, _, _)| *pc)
}

fn has_prior_noid_same_register_packet_range_for_guard(
    states: &[VerifierInsn],
    source_events: &[SourceEvent],
    before_idx: usize,
    reg: u8,
    required: u32,
    current: &RegState,
    guard_source: &SourceLocation,
) -> bool {
    if current.id.is_none() {
        return false;
    }
    let Some(guard_derivation) = packet_guard_derivation_source(source_events, guard_source) else {
        return false;
    };
    for state in states[..before_idx].iter().rev() {
        let Some(prior) = state.regs.get(&reg) else {
            continue;
        };
        if prior.reg_type != "pkt" {
            return false;
        }
        if prior.id.is_some() {
            return false;
        }
        if prior.packet_range.is_some_and(|range| range >= required)
            && same_packet_offset(prior, current)
            && source_for_pc(source_events, state.pc)
                .is_some_and(|source| same_source_location(source, guard_derivation))
        {
            return true;
        }
    }
    false
}

fn same_packet_offset(left: &RegState, right: &RegState) -> bool {
    left.offset
        .zip(right.offset)
        .is_some_and(|(left, right)| left == right)
}

fn packet_guard_derivation_source<'a>(
    source_events: &'a [SourceEvent],
    guard_source: &SourceLocation,
) -> Option<&'a SourceLocation> {
    let guard_var = packet_guard_pointer_variable(&guard_source.text)?;
    source_events
        .iter()
        .filter(|event| event.source.path == guard_source.path)
        .filter(|event| event.source.line < guard_source.line)
        .filter(|event| looks_like_packet_pointer_derivation(&event.source.text))
        .filter(|event| {
            packet_derivation_lhs_variable(&event.source.text)
                .as_deref()
                .is_some_and(|lhs| lhs == guard_var)
        })
        .max_by_key(|event| event.source.line)
        .map(|event| &event.source)
}

fn packet_guard_pointer_variable(text: &str) -> Option<String> {
    let text = text.trim();
    let condition = text.strip_prefix("if ")?.trim();
    let condition = condition
        .strip_prefix('(')
        .and_then(|condition| condition.strip_suffix(')'))
        .unwrap_or(condition);
    let before_data_end = condition
        .split_once("> data_end")
        .map(|(left, _)| left)
        .or_else(|| condition.split_once(">= data_end").map(|(left, _)| left))?;
    identifier_tokens(before_data_end).into_iter().next()
}

fn packet_derivation_lhs_variable(text: &str) -> Option<String> {
    let (lhs, _) = text.split_once('=')?;
    identifier_tokens(lhs).into_iter().last()
}

fn packet_guard_proves_rejected_access(
    guard: &RegState,
    current: &RegState,
    required: u32,
    mixed_id_same_register_history: bool,
) -> Option<u32> {
    if guard.reg_type != "pkt" || current.reg_type != "pkt" {
        return None;
    }
    let range = guard.packet_range?;
    if range < required
        || current
            .packet_range
            .is_some_and(|current| current >= required)
    {
        return None;
    }
    match (guard.id, current.id) {
        (Some(guard_id), Some(current_id)) if guard_id == current_id => Some(range),
        (None, None) => Some(range),
        _ => {
            let guard_offset = guard.offset.and_then(|offset| u32::try_from(offset).ok())?;
            (mixed_id_same_register_history
                && guard_offset >= required
                && scalar_range_has_any_bound(current)
                && scalar_ranges_match(guard, current))
            .then_some(range)
        }
    }
}

pub(super) fn scalar_range_events(
    states: &[VerifierInsn],
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_scalar_guard(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::ScalarRange,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "scalar range guard is visible before the rejected operation".to_string(),
        });
    }

    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        text.contains("volatile") || text.contains("asm volatile")
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::ScalarRange,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "bounded scalar proof can be lost when the checked value is materialized as a different verifier value"
                .to_string(),
        });
        return events;
    }

    let Some(reg) = register else {
        return events;
    };
    if let Some((pc, state)) = latest_unsafe_scalar_state(states, terminal_pc, reg) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::VerifierState,
            obligation: ProofObligation::ScalarRange,
            pc: Some(pc),
            source: source_for_pc(source_events, pc).cloned(),
            register,
            detail: format!(
                "verifier still sees R{reg} as {}, so the required scalar or map-value bound is not available at the use",
                verifier_value_summary(state)
            ),
        });
    }
    events
}

pub(super) fn nullable_pointer_events(
    states: &[VerifierInsn],
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_null_check(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::NullablePointer,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "non-null proof is established in this branch".to_string(),
        });
    }

    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_nullable_return(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::NullablePointer,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "nullable pointer returned here reaches the use without a verifier-visible non-null proof"
                .to_string(),
        });
        return events;
    }

    let Some(reg) = register else {
        return events;
    };
    if let Some((pc, kind)) = latest_nullable_state(states, terminal_pc, reg) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::VerifierState,
            obligation: ProofObligation::NullablePointer,
            pc: Some(pc),
            source: source_for_pc(source_events, pc).cloned(),
            register,
            detail: format!("verifier still tracks R{reg} as nullable type {kind}"),
        });
    }
    events
}

pub(super) fn stack_initialized_events(
    source_events: &[SourceEvent],
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_stack_initialization(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::StackInitialized,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "some stack/register initialization is visible before the rejected use"
                .to_string(),
        });
    }
    events
}

pub(super) fn reference_lifecycle_events(
    source_events: &[SourceEvent],
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_reference_acquire(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::ReferenceLifecycle,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "verifier-tracked reference is acquired here".to_string(),
        });
    }
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_reference_release(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::ReferenceLifecycle,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "reference release is visible on one path".to_string(),
        });
    }
    if let Some(source) = rejected_source {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::ReferenceLifecycle,
            pc: None,
            source: Some(source.clone()),
            register,
            detail: "release proof must hold on every exit path, not only the path shown above"
                .to_string(),
        });
    }
    events
}

pub(super) fn environment_capability_events(
    source_events: &[SourceEvent],
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(source) = rejected_source.filter(|source| source.text.contains("bpf_")) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::EnvironmentCapability,
            pc: None,
            source: Some(source.clone()),
            register,
            detail: "this helper call requires a program type, attach type, or kernel capability not available to the load"
                .to_string(),
        });
        return events;
    }
    if let Some(event) =
        latest_source_before(source_events, rejected_source, |text| text.contains("bpf_"))
    {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::EnvironmentCapability,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "this helper call requires a program type, attach type, or kernel capability not available to the load"
                .to_string(),
        });
    }
    events
}
