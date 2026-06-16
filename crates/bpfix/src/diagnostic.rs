use anyhow::Result;
use bpfanalysis::verifier_log::{
    atomic_memory_access_width, call_target_from_instruction_tail, conditional_branch_registers,
    direct_call_target_from_instruction_tail, instruction_adds_register,
    instruction_assigns_register, instruction_destination_register, instruction_on_log_line,
    instruction_reads_register, instruction_register_copy_source,
    instruction_single_register_rhs_source, instruction_site_before_line,
    instructions_in_line_range, is_verifier_error_line, is_verifier_fragment_boundary,
    latest_nullable_state, latest_reg_state_at_or_before_instruction, latest_reg_state_before,
    latest_reg_state_before_instruction, latest_reg_state_before_instruction_with_frame,
    latest_reg_state_before_instruction_with_origin, latest_reg_state_index_before,
    latest_unsafe_scalar_state, latest_verifier_state_before_instruction,
    loose_register_operands as register_operands, map_value_access_range_may_exceed_value_size,
    map_value_range_may_exceed_value_size, map_value_remaining_capacity,
    map_value_variable_max_offset, memory_access_base_register, memory_access_is_atomic,
    memory_access_is_load, memory_access_is_store, memory_access_offset, memory_access_width,
    parse_i64_after, parse_instruction_line, parse_u32_after, scalar_range_has_any_bound,
    scalar_range_max_i64, scalar_range_may_be_negative, scalar_range_may_include_zero,
    scalar_range_min_i64, scalar_range_upper_unbounded_or_too_large, scalar_ranges_match,
    scalar_state_upper_bound_at_most, stack_access_range, stack_value_range,
    terminal_instruction_access_width, terminal_instruction_memory_offset,
    terminal_instruction_site, verifier_fragment_start_line,
    verifier_states_with_branch_deltas_from_log, verifier_value_summary, CallbackKind, RegState,
    StackByteRange, StackState, VerifierInsn, VerifierInsnKind,
    VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;
use crate::proof::{instantiate_required_proof, packet_required_range, RequiredProof};
use crate::source::{
    collect_source_events, latest_source_before, looks_like_null_check, looks_like_nullable_return,
    looks_like_packet_bounds_check, looks_like_reference_acquire, looks_like_reference_release,
    looks_like_scalar_guard, looks_like_stack_initialization, source_for_pc, terminal_source,
    SourceEvent, SourceLocation,
};

const MAX_BPF_STACK_DEPTH: i32 = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierLogAnalysis {
    pub state_count: usize,
    pub required_proof: RequiredProof,
    pub events: Vec<ProofEvent>,
    pub signals: Vec<ProofSignal>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofEventRole {
    ProofEstablished,
    ProofLost,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofEventEvidence {
    VerifierState,
    SourceComment,
    TerminalVerifier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofEvent {
    pub role: ProofEventRole,
    pub evidence: ProofEventEvidence,
    pub obligation: ProofObligation,
    pub pc: Option<usize>,
    pub source: Option<SourceLocation>,
    pub register: Option<u8>,
    pub detail: String,
}

mod context_signal;
mod dynptr_signal;
mod helper_contract_signal;
mod irq_signal;
mod iterator_signal;
mod nullable_signal;
mod protocol_signal;
mod signal;
mod stack_signal;
mod type_contract_signal;
pub use signal::ProofSignal;

#[cfg(test)]
pub fn analyze_verifier_log(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    terminal_error: &str,
    terminal_call_target: Option<&str>,
    obligation: ProofObligation,
) -> Result<VerifierLogAnalysis> {
    analyze_verifier_log_with_context(VerifierLogContext {
        log,
        full_log: log,
        object_sections: &[],
        terminal_pc,
        terminal_line,
        terminal_error,
        terminal_call_target,
        obligation,
    })
}

pub struct VerifierLogContext<'a> {
    pub log: &'a str,
    pub full_log: &'a str,
    pub object_sections: &'a [String],
    pub terminal_pc: Option<usize>,
    pub terminal_line: Option<usize>,
    pub terminal_error: &'a str,
    pub terminal_call_target: Option<&'a str>,
    pub obligation: ProofObligation,
}

pub fn analyze_verifier_log_with_context(
    context: VerifierLogContext<'_>,
) -> Result<VerifierLogAnalysis> {
    let VerifierLogContext {
        log,
        full_log,
        object_sections,
        terminal_pc,
        terminal_line,
        terminal_error,
        terminal_call_target,
        obligation,
    } = context;
    let branch_states = verifier_states_with_branch_deltas_from_log(log)?;
    let states = branch_states
        .iter()
        .filter(|state| state.kind != VerifierInsnKind::BranchDeltaState)
        .cloned()
        .collect::<Vec<_>>();
    let source_events = collect_source_events(log);
    let required_proof = instantiate_required_proof(
        terminal_error,
        terminal_call_target,
        terminal_pc,
        &states,
        obligation,
    );
    let obligation = required_proof.obligation;
    let register = required_proof.register;
    let rejected_source = terminal_source(&source_events, terminal_pc);
    let mut events = Vec::new();

    match obligation {
        ProofObligation::PointerProvenance => {
            events.extend(pointer_provenance_events(
                &states,
                &source_events,
                terminal_pc,
                rejected_source.as_ref(),
                register,
            ));
        }
        ProofObligation::PacketBounds => {
            events.extend(packet_bounds_events(&PacketBoundsEventContext {
                log,
                states: &states,
                branch_states: &branch_states,
                source_events: &source_events,
                terminal_pc,
                terminal_error,
                rejected_source: rejected_source.as_ref(),
                register,
            }))
        }
        ProofObligation::ScalarRange => events.extend(scalar_range_events(
            &states,
            &source_events,
            terminal_pc,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::NullablePointer => events.extend(nullable_pointer_events(
            &states,
            &source_events,
            terminal_pc,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::StackInitialized => events.extend(stack_initialized_events(
            &source_events,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::ReferenceLifecycle => events.extend(reference_lifecycle_events(
            &source_events,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::EnvironmentCapability => events.extend(environment_capability_events(
            &source_events,
            rejected_source.as_ref(),
            register,
        )),
        _ => {}
    }

    events.push(ProofEvent {
        role: ProofEventRole::Rejected,
        evidence: ProofEventEvidence::TerminalVerifier,
        obligation,
        pc: terminal_pc,
        source: rejected_source,
        register,
        detail: required_proof.rejection_detail.clone(),
    });
    let signal_context = ProofSignalContext {
        log,
        full_log,
        object_sections,
        terminal_error,
        terminal_call_target,
        obligation,
        terminal_pc,
        terminal_line,
        register,
        states: &states,
        branch_states: &branch_states,
        source_events: &source_events,
        events: &events,
    };
    let signals = proof_signals(signal_context);

    Ok(VerifierLogAnalysis {
        state_count: states.len(),
        required_proof,
        events,
        signals,
    })
}

fn pointer_provenance_events(
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

    if let Some((pc, kind)) = latest_pointer_to_scalar_transition(states, terminal_pc, register) {
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

fn latest_pointer_to_scalar_transition(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    register: Option<u8>,
) -> Option<(usize, String)> {
    let reg = register?;
    let mut latest_pointer: Option<(usize, String)> = None;
    let mut latest_loss = None;
    for state in states {
        if terminal_pc.is_some_and(|pc| state.pc > pc) {
            continue;
        }
        let Some(reg_state) = state.regs.get(&reg) else {
            continue;
        };
        if is_pointer_state(reg_state) {
            latest_pointer = Some((state.pc, reg_state.reg_type.clone()));
        } else if reg_state.reg_type == "scalar" {
            if let Some((_, pointer_kind)) = latest_pointer.as_ref() {
                latest_loss = Some((state.pc, pointer_kind.clone()));
            }
        }
    }
    latest_loss
}

fn is_pointer_state(state: &RegState) -> bool {
    state.reg_type != "scalar" && state.reg_type != "fp"
}

struct PacketBoundsEventContext<'a> {
    log: &'a str,
    states: &'a [VerifierInsn],
    branch_states: &'a [VerifierInsn],
    source_events: &'a [SourceEvent],
    terminal_pc: Option<usize>,
    terminal_error: &'a str,
    rejected_source: Option<&'a SourceLocation>,
    register: Option<u8>,
}

fn packet_bounds_events(context: &PacketBoundsEventContext<'_>) -> Vec<ProofEvent> {
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

fn scalar_range_events(
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

fn nullable_pointer_events(
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

fn stack_initialized_events(
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

fn reference_lifecycle_events(
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

fn environment_capability_events(
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

struct ProofSignalContext<'a> {
    log: &'a str,
    full_log: &'a str,
    object_sections: &'a [String],
    terminal_error: &'a str,
    terminal_call_target: Option<&'a str>,
    obligation: ProofObligation,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    register: Option<u8>,
    states: &'a [VerifierInsn],
    branch_states: &'a [VerifierInsn],
    source_events: &'a [SourceEvent],
    events: &'a [ProofEvent],
}

fn terminal_fragment_start(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
) -> usize {
    context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line))
}

#[rustfmt::skip]
fn proof_signals(context: ProofSignalContext<'_>) -> Vec<ProofSignal> {
    let mut signals = Vec::new();
    let c = &context;

    macro_rules! push_signals {
        ($($signal:expr => $predicate:expr),* $(,)?) => { $( if $predicate { signals.push($signal); } )* };
    }
    macro_rules! push_optional_signals {
        ($($predicate:expr),* $(,)?) => { $( if let Some(signal) = $predicate { signals.push(signal); } )* };
    }
    macro_rules! push_fallback_signal {
        ($signal:expr => $predicate:expr) => { if signals.is_empty() && $predicate { signals.push($signal); } };
    }
    macro_rules! push_fallback_opt {
        ($predicate:expr) => { if signals.is_empty() { push_optional_signals!($predicate); } };
    }

    push_signals! {
        ProofSignal::WideStackAlignment => stack_alignment_lowering_signal(c),
        ProofSignal::AtomicMemoryAccessScalarBase => atomic_memory_alignment_scalar_base(c),
        ProofSignal::LoopBackEdgeStateRepeats => loop_back_edge_state_repeats(c),
        ProofSignal::PointerShiftDropsProvenance => pointer_shift_lowering_signal(c),
        ProofSignal::ModifiedContextPointer => modified_context_pointer_lowering_signal(c),
        ProofSignal::SharedInstructionPointerMerge => shared_instruction_pointer_merge_signal(c),
        ProofSignal::SubprogramContextArgumentDropped => subprogram_context_argument_dropped_signal(c),
    }
    if c.source_events.is_empty() {
        push_optional_signals!(bytecode_only_lowering_signal(c.log, c.terminal_error, c.obligation, c.terminal_pc, c.register, c.states));
    }
    push_optional_signals!(verifier_precision_signal(c), packet_verifier_precision_signal(c));

    push_signals! {
        ProofSignal::ContextAccessSourceArgumentMismatch => context_signal::bpf_prog_context_argument_mismatch(c),
        ProofSignal::TraceContextScalarArgumentMismatch => context_signal::trace_context_scalar_argument_dereference(c),
        ProofSignal::ContextFieldUnavailable => context_signal::context_field_unavailable(c),
        ProofSignal::PacketContextFieldAccessInUnsupportedProgram => context_signal::packet_context_field_access_in_unsupported_program(c),
        ProofSignal::KernelObjectFieldAccessMismatch => context_signal::kernel_object_field_access_mismatch(c),
        ProofSignal::ExceptionThrowWithLiveReference => protocol_signal::exception_throw_with_live_reference(c.log, c.terminal_pc, c.terminal_line, c.states),
        ProofSignal::ReferenceLiveAtExit => protocol_signal::reference_live_at_exit(c),
        ProofSignal::ExceptionCallbackProtocolViolation => protocol_signal::exception_callback_protocol_violation(c),
        ProofSignal::MapPointerArgumentScalarZero => helper_contract_signal::map_pointer_argument_scalar_zero(c),
        ProofSignal::BtfFuncInfoMissing => helper_contract_signal::btf_func_info_missing(c),
        ProofSignal::SubprogramReferenceMetadataMissing => helper_contract_signal::subprogram_reference_metadata_missing(c),
        ProofSignal::MapLookupKeyArgumentUnreadable => stack_signal::map_lookup_key_argument_unreadable(c),
        ProofSignal::UnreadableProgramEntryArgument => stack_signal::unreadable_program_entry_argument(c),
        ProofSignal::UnreadableHelperArgument => stack_signal::unreadable_helper_argument(c),
        ProofSignal::MapPointerRawAccessContract => helper_contract_signal::map_pointer_raw_access_contract(c),
        ProofSignal::PerfEventOutputPacketAccess => helper_contract_signal::perf_event_output_packet_access(c),
        ProofSignal::UnreadableReturnRegister => stack_signal::unreadable_return_register(c),
        ProofSignal::LegacySkbLoadUnreadableRegister => stack_signal::legacy_skb_load_unreadable_register(c),
        ProofSignal::HelperStackReadExceedsInitializedRange => stack_signal::helper_stack_read_exceeds_initialized_range(c),
        ProofSignal::HelperStackWriteBeyondFrame => stack_signal::helper_stack_write_beyond_frame(c),
        ProofSignal::DynptrUninitializedArgument => dynptr_signal::dynptr_uninitialized_argument(c),
        ProofSignal::DynptrReferencedSlotOverwrite => dynptr_signal::dynptr_referenced_slot_overwrite(c),
        ProofSignal::DynptrReadonlyPacketWrite => dynptr_signal::dynptr_readonly_packet_write(c),
        ProofSignal::DynptrStackSlotWriteOverlap => dynptr_signal::dynptr_stack_slot_write_overlap(c),
        ProofSignal::DynptrStackStorageAccess => dynptr_signal::dynptr_stack_storage_access(c),
        ProofSignal::DynptrHelperArgumentStateMismatch => dynptr_signal::dynptr_helper_argument_state_mismatch(c),
        ProofSignal::DynptrReleaseUnacquiredReference => dynptr_signal::dynptr_release_unacquired_reference(c),
        ProofSignal::DynptrSliceVariableLength => dynptr_signal::dynptr_slice_variable_length(c),
        ProofSignal::IteratorHelperArgumentStateMismatch => iterator_signal::iterator_helper_argument_state_mismatch(c),
        ProofSignal::IteratorStackStorageAccess => iterator_signal::iterator_stack_storage_access(c),
        ProofSignal::IrqFlagStateMismatch => irq_signal::irq_flag_state_mismatch(c),
        ProofSignal::IrqRestoreOrderMismatch => irq_signal::irq_restore_order_mismatch(c),
        ProofSignal::IrqRestoreHelperClassMismatch => irq_signal::irq_restore_helper_class_mismatch(c),
        ProofSignal::IrqStateLiveAtExit => irq_signal::irq_state_live_at_exit(c),
        ProofSignal::SleepableCallInNonSleepableContext => protocol_signal::sleepable_call_in_non_sleepable_context(c),
        ProofSignal::CallbackCallWhileLocked => callback_call_while_locked(c),
        ProofSignal::NullablePointerUseWithoutProof => nullable_signal::nullable_pointer_use_without_proof(c),
        ProofSignal::ModernBpfObjectProtocolViolation => protocol_signal::modern_bpf_object_protocol_violation(c),
        ProofSignal::KfuncArgumentTypeMismatch => type_contract_signal::kfunc_argument_type_mismatch(c),
        ProofSignal::TrustedNullableArgument => nullable_signal::trusted_nullable_argument(c),
        ProofSignal::VerifierTypeContractMismatch => type_contract_signal::verifier_type_contract_mismatch(c),
        ProofSignal::MemoryObjectAccessOutOfBounds => memory_object_access_out_of_bounds(c),
        ProofSignal::ReturnRangeOutOfBounds => return_range_out_of_bounds(c),
        ProofSignal::StackVariableOffsetOutOfBounds => stack_variable_offset_out_of_bounds(c),
        ProofSignal::ScalarRangeUnsafeAtUse => scalar_range_unsafe_at_use(c),
        ProofSignal::PacketPointerProofLostAfterBoundsCheck => c.events.iter().any(packet_proof_lost_after_bounds_check),
        ProofSignal::PacketRangeProofLostBeforeAccess => packet_range_proof_lost_before_access(c.events),
        ProofSignal::PacketGuardUndercoversAccess => packet_guard_undercovers_access(c),
        ProofSignal::PacketAccessWithoutBoundsProof => packet_access_without_bounds_proof(c),
        ProofSignal::MapValueWideAccess => map_value_wide_access(c.log, c.terminal_error, c.terminal_pc, c.terminal_line, c.register, c.branch_states),
        ProofSignal::MapValueCheckedOffsetRelationLost => map_value_checked_offset_relation_lost(c.terminal_error, c.terminal_pc, c.register, c.states, c.events, c.source_events),
        ProofSignal::MapValueGuardExceedsValueSize => map_value_guard_exceeds_value_size(c),
        ProofSignal::MapValueAccessOutOfBounds => map_value_access_out_of_bounds(c),
    }

    push_fallback_opt!(stale_pointer_after_invalidating_helper(c));
    push_fallback_signal!(ProofSignal::OpaqueScalarPointerDereference => opaque_scalar_pointer_dereference(c));
    push_fallback_signal!(ProofSignal::NullScalarDereferenceAfterPointerProof => nullable_signal::null_scalar_dereference_after_pointer_proof(c));
    push_fallback_signal!(ProofSignal::ScalarValueUsedAsPointer => scalar_value_used_as_pointer(c));
    push_fallback_signal!(ProofSignal::ProhibitedPointerArithmetic => prohibited_pointer_arithmetic(c));

    // Same-rank signals keep registry order; runtime selection relies on stable sorting.
    signals.sort_by_key(|signal| signal.selection_rank());
    signals
}

fn bytecode_only_lowering_signal(
    log: &str,
    terminal_error: &str,
    obligation: ProofObligation,
    terminal_pc: Option<usize>,
    register: Option<u8>,
    states: &[VerifierInsn],
) -> Option<ProofSignal> {
    match obligation {
        ProofObligation::PointerProvenance => {
            let reg = register?;
            if alu32_pointer_copy_drops_provenance(log, reg) {
                return Some(ProofSignal::Alu32PointerCopyDropsProvenance);
            }
            if same_pc_has_pointer_proof(states, terminal_pc, reg) {
                return Some(ProofSignal::SharedInstructionPathProofLoss);
            }
            if invalid_scalar_memory_load_from_constant(terminal_error, states, terminal_pc, reg) {
                return Some(ProofSignal::ConstantScalarMemoryLoad);
            }
            None
        }
        ProofObligation::StackInitialized => {
            let reg = register?;
            if terminal_error.contains("!read_ok")
                && same_pc_has_register_state(states, terminal_pc, reg)
            {
                Some(ProofSignal::SharedInstructionUninitializedRegister)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn alu32_pointer_copy_drops_provenance(log: &str, reg: u8) -> bool {
    let copy = format!("(bc) w{reg} = w");
    let scalar = format!("R{reg}_w=scalar");
    log.lines().any(|line| {
        line.contains(&copy)
            && line.contains(&scalar)
            && (line.contains("=pkt(") || line.contains("=ctx("))
    })
}

fn same_pc_has_pointer_proof(states: &[VerifierInsn], terminal_pc: Option<usize>, reg: u8) -> bool {
    states
        .iter()
        .filter(|state| terminal_pc.is_some_and(|pc| state.pc == pc))
        .filter_map(|state| state.regs.get(&reg))
        .any(is_pointer_state)
}

fn same_pc_has_register_state(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> bool {
    states
        .iter()
        .filter(|state| terminal_pc.is_some_and(|pc| state.pc == pc))
        .any(|state| state.regs.contains_key(&reg))
}

fn invalid_scalar_memory_load_from_constant(
    terminal_error: &str,
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> bool {
    if !terminal_error.contains("invalid mem access 'scalar'") {
        return false;
    }
    latest_reg_state_before(states, terminal_pc, reg)
        .and_then(|state| state.exact_value)
        .is_some_and(|value| (1..=4096).contains(&value))
}

fn instruction_is_bpf_exit(tail: &str) -> bool {
    let mut tokens = tail.split_whitespace();
    tokens.next() == Some("(95)") && tokens.next() == Some("exit")
}

fn terminal_required_return_range(message: &str) -> Option<(i64, i64)> {
    let (_, rest) = message.split_once("should have been in [")?;
    let (range, _) = rest.split_once(']')?;
    let (lo, hi) = range.split_once(',')?;
    Some((parse_signed_decimal(lo)?, parse_signed_decimal(hi)?))
}

fn scalar_state_outside_required_range(state: &RegState, required: (i64, i64)) -> bool {
    if state.reg_type != "scalar" {
        return false;
    }
    if let Some(value) = state.exact_u64() {
        return exact_u64_outside_required_range(value, required);
    }
    if let Some(value) = state.exact_u32() {
        return exact_u32_outside_required_range(value, required);
    }
    let (required_min, required_max) = required;
    if let (Some(smin), Some(smax)) = (state.range.smin, state.range.smax) {
        return smin < required_min || smax > required_max;
    }
    if let Some((required_min, required_max)) = nonnegative_required_range_as_u64(required) {
        if let (Some(umin), Some(umax)) = (state.range.umin, state.range.umax) {
            return umin < required_min || umax > required_max;
        }
    }
    if let (Some(smin), Some(smax)) = (state.range.smin32, state.range.smax32) {
        return i64::from(smin) < required_min || i64::from(smax) > required_max;
    }
    if let Some((required_min, required_max)) = nonnegative_required_range_as_u64(required) {
        if let (Some(umin), Some(umax)) = (state.range.umin32, state.range.umax32) {
            return u64::from(umin) < required_min || u64::from(umax) > required_max;
        }
    }
    true
}

fn exact_u64_outside_required_range(value: u64, required: (i64, i64)) -> bool {
    let signed_value = value as i64;
    if signed_value >= required.0 && signed_value <= required.1 {
        return false;
    }
    nonnegative_required_range_as_u64(required).is_none_or(|(min, max)| value < min || value > max)
}

fn exact_u32_outside_required_range(value: u32, required: (i64, i64)) -> bool {
    let signed_value = i64::from(value as i32);
    if signed_value >= required.0 && signed_value <= required.1 {
        return false;
    }
    nonnegative_required_range_as_u64(required)
        .is_none_or(|(min, max)| u64::from(value) < min || u64::from(value) > max)
}

fn nonnegative_required_range_as_u64(required: (i64, i64)) -> Option<(u64, u64)> {
    let min = u64::try_from(required.0).ok()?;
    let max = u64::try_from(required.1).ok()?;
    Some((min, max))
}

fn callback_call_while_locked(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("function calls are not allowed") && terminal.contains("holding a lock"))
    {
        return false;
    }
    let Some(terminal_instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if call_target_from_instruction_tail(terminal_instruction.tail).is_none() {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, terminal_instruction);
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

fn latest_register_assignment<'a>(
    states: &[VerifierInsn],
    log: &'a str,
    fragment_start: usize,
    before_line: usize,
    reg: u8,
    frame: usize,
) -> Option<TerminalInstruction<'a>> {
    instructions_in_line_range(log, fragment_start, before_line)
        .filter(|instruction| {
            instruction_assigns_register(instruction.tail, reg)
                && instruction_frame(states, *instruction, fragment_start)
                    .is_none_or(|assigned_frame| assigned_frame == frame)
        })
        .last()
}

fn scalar_value_used_as_pointer(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PointerProvenance {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    let scalar_mem_access = terminal.contains("invalid mem access 'scalar'")
        || terminal.contains("invalid mem access 'inv'");
    let pkt_end_arithmetic =
        terminal.contains("pointer arithmetic") && terminal_mentions_pkt_end(&terminal);
    if !scalar_mem_access && !pkt_end_arithmetic {
        return false;
    }
    let Some(reg) = context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
    else {
        return false;
    };
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if scalar_mem_access && memory_access_base_register(instruction.tail) != Some(reg) {
        return false;
    }
    if pkt_end_arithmetic && register_operands(instruction.tail).first().copied() != Some(reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
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

fn opaque_scalar_pointer_dereference(context: &ProofSignalContext<'_>) -> bool {
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
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if memory_access_base_register(instruction.tail) != Some(reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some((state, _, frame)) = latest_reg_state_before_instruction_with_origin(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    ) else {
        return false;
    };
    if state.reg_type != "scalar" {
        return false;
    }
    let Some((stack_load, stack_range)) = latest_stack_pointer_value_load_source(
        context.branch_states,
        context.log,
        instruction,
        fragment_start,
        reg,
        frame,
    ) else {
        return false;
    };
    probe_read_helper_wrote_stack_range(
        context.branch_states,
        context.log,
        fragment_start,
        stack_load.line,
        stack_range,
        frame,
    )
}

fn latest_stack_pointer_value_load_source<'a>(
    states: &[VerifierInsn],
    log: &'a str,
    terminal_instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: u8,
    frame: usize,
) -> Option<(TerminalInstruction<'a>, StackByteRange)> {
    latest_stack_pointer_value_load_source_inner(
        states,
        log,
        terminal_instruction.line,
        fragment_start,
        reg,
        frame,
        0,
    )
}

fn latest_stack_pointer_value_load_source_inner<'a>(
    states: &[VerifierInsn],
    log: &'a str,
    before_line: usize,
    fragment_start: usize,
    reg: u8,
    frame: usize,
    depth: usize,
) -> Option<(TerminalInstruction<'a>, StackByteRange)> {
    if depth > 8 {
        return None;
    }
    instructions_in_line_range(log, fragment_start, before_line)
        .filter(|instruction| {
            instruction_assigns_register(instruction.tail, reg)
                && instruction_frame(states, *instruction, fragment_start)
                    .is_none_or(|assigned_frame| assigned_frame == frame)
        })
        .last()
        .and_then(|instruction| {
            if memory_access_is_load(instruction.tail)
                && memory_access_width(instruction.tail) == Some(8)
                && instruction_destination_register(instruction.tail) == Some(reg)
            {
                let base_reg = memory_access_base_register(instruction.tail)?;
                let (base, base_frame) = latest_reg_state_before_instruction_with_frame(
                    states,
                    instruction,
                    fragment_start,
                    base_reg,
                )?;
                if base_frame != frame
                    || base.reg_type != "fp"
                    || reg_state_has_variable_offset(base)
                {
                    return None;
                }
                return Some((
                    instruction,
                    stack_memory_access_range(base, instruction.tail)?,
                ));
            }
            let source = instruction_register_copy_source(instruction.tail, reg)?;
            latest_stack_pointer_value_load_source_inner(
                states,
                log,
                instruction.line,
                fragment_start,
                source,
                frame,
                depth + 1,
            )
        })
}

fn probe_read_helper_wrote_stack_range(
    states: &[VerifierInsn],
    log: &str,
    fragment_start: usize,
    before_line: usize,
    access: StackByteRange,
    frame: usize,
) -> bool {
    latest_stack_range_writer(states, log, fragment_start, before_line, access, frame).is_some_and(
        |writer| {
            matches!(
                writer,
                StackRangeWriter::ProbeReadValue { written } if written.contains_range(access)
            )
        },
    )
}

#[derive(Clone, Copy)]
enum StackRangeWriter {
    ProbeReadValue { written: StackByteRange },
    Other,
}

fn latest_stack_range_writer(
    states: &[VerifierInsn],
    log: &str,
    fragment_start: usize,
    before_line: usize,
    access: StackByteRange,
    frame: usize,
) -> Option<StackRangeWriter> {
    let instructions =
        instructions_in_line_range(log, fragment_start, before_line).collect::<Vec<_>>();
    instructions.iter().rev().copied().find_map(|instruction| {
        if stack_store_overlaps_range(states, instruction, fragment_start, access, frame) {
            return Some(StackRangeWriter::Other);
        }
        let target = call_target_from_instruction_tail(instruction.tail)?;
        if let Some(written) =
            helper_stack_output_range(states, instruction, fragment_start, target, frame)
        {
            if written.overlaps(access) {
                if probe_read_value_helper(target) {
                    return Some(StackRangeWriter::ProbeReadValue { written });
                }
                return Some(StackRangeWriter::Other);
            }
        }
        if helper_stack_argument_starts_at_access(
            states,
            instruction,
            fragment_start,
            access,
            frame,
        ) {
            return Some(StackRangeWriter::Other);
        }
        None
    })
}

fn stack_store_overlaps_range(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    access: StackByteRange,
    frame: usize,
) -> bool {
    if !memory_access_is_store(instruction.tail) {
        return false;
    }
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    let Some((base, base_frame)) = latest_reg_state_before_instruction_with_frame(
        states,
        instruction,
        fragment_start,
        base_reg,
    ) else {
        return false;
    };
    if base_frame != frame || base.reg_type != "fp" || reg_state_has_variable_offset(base) {
        return false;
    }
    stack_memory_access_range(base, instruction.tail)
        .is_some_and(|written| written.overlaps(access))
}

fn helper_stack_output_range(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
    frame: usize,
) -> Option<StackByteRange> {
    let (write_reg, len_reg) = stack_output_helper_signature(target)?;
    let (arg, arg_frame) = latest_reg_state_for_call_argument_with_frame(
        states,
        instruction,
        fragment_start,
        Some(instruction.line),
        write_reg,
    )?;
    if arg_frame != frame || arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
        return None;
    }
    let len = helper_exact_u64_argument(states, instruction, fragment_start, len_reg)?;
    let len = i16::try_from(len).ok()?;
    let offset = i16::try_from(arg.offset.unwrap_or_default()).ok()?;
    stack_value_range(offset, len)
}

fn probe_read_value_helper(target: &str) -> bool {
    probe_read_value_helper_signature(target).is_some()
}

fn probe_read_value_helper_signature(target: &str) -> Option<(u8, u8)> {
    match target {
        "bpf_probe_read"
        | "4"
        | "bpf_probe_read_user"
        | "112"
        | "bpf_probe_read_kernel"
        | "113" => Some((1, 2)),
        _ => None,
    }
}

fn stack_output_helper_signature(target: &str) -> Option<(u8, u8)> {
    match target {
        "bpf_probe_read"
        | "4"
        | "bpf_probe_read_user"
        | "112"
        | "bpf_probe_read_kernel"
        | "113"
        | "bpf_probe_read_str"
        | "45"
        | "bpf_probe_read_user_str"
        | "114"
        | "bpf_probe_read_kernel_str"
        | "115"
        | "bpf_get_current_comm"
        | "16"
        | "bpf_copy_from_user"
        | "bpf_copy_from_user_task"
        | "bpf_dynptr_read"
        | "bpf_snprintf" => Some((1, 2)),
        "bpf_d_path" | "bpf_get_stack" | "bpf_get_task_stack" => Some((2, 3)),
        "bpf_skb_load_bytes" | "26" | "bpf_skb_load_bytes_relative" | "bpf_xdp_load_bytes" => {
            Some((3, 4))
        }
        _ => None,
    }
}

fn helper_stack_argument_starts_at_access(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    access: StackByteRange,
    frame: usize,
) -> bool {
    call_target_from_instruction_tail(instruction.tail).is_some()
        && (1..=5).any(|reg| {
            let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
                states,
                instruction,
                fragment_start,
                Some(instruction.line),
                reg,
            ) else {
                return false;
            };
            if arg_frame != frame || arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
                return false;
            }
            i16::try_from(arg.offset.unwrap_or_default()) == Ok(access.start())
        })
}

fn helper_exact_u64_argument(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: u8,
) -> Option<u64> {
    latest_reg_state_before_instruction(states, instruction, fragment_start, reg)?
        .exact_scalar_value()
}

fn stale_pointer_after_invalidating_helper(
    context: &ProofSignalContext<'_>,
) -> Option<ProofSignal> {
    if context.obligation != ProofObligation::PointerProvenance {
        return None;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid mem access 'scalar'")
        || terminal.contains("invalid mem access 'inv'"))
    {
        return None;
    }
    let reg = context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))?;
    let instruction =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)?;
    if memory_access_base_register(instruction.tail) != Some(reg) {
        return None;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let (state, state_log_line, state_frame) = latest_reg_state_before_instruction_with_origin(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    )?;
    let (pointer_kind, invalidated) = if let Some(pointer_kind) =
        stale_data_pointer_kind(context, state, state_log_line, reg)
    {
        if register_assigned_between(
            context.branch_states,
            context.log,
            reg,
            state_frame,
            fragment_start,
            state_log_line,
            instruction.line,
        ) {
            return None;
        }
        let invalidated =
            invalidating_helper_between(context, state_log_line, instruction.line, pointer_kind)
                || matches!(
                    pointer_kind,
                    StaleDataPointerKind::DynptrData(origin)
                        if dynptr_data_invalidated_by_callback_write(
                            context,
                            state_log_line,
                            instruction.line,
                            origin,
                        )
                );
        (pointer_kind, invalidated)
    } else {
        let (origin, origin_log_line) = prior_dynptr_data_pointer_before_instruction(
            context,
            instruction,
            fragment_start,
            reg,
        )?;
        if !dynptr_data_invalidated_by_callback_write(
            context,
            origin_log_line,
            instruction.line,
            origin,
        ) {
            return None;
        }
        (StaleDataPointerKind::DynptrData(origin), true)
    };
    if !invalidated {
        return None;
    }
    Some(match pointer_kind {
        StaleDataPointerKind::Packet => ProofSignal::StalePointerAfterInvalidatingHelper,
        StaleDataPointerKind::DynptrData(_) => ProofSignal::DynptrDataPointerInvalidatedBeforeUse,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StaleDataPointerKind {
    Packet,
    DynptrData(DynptrDataOrigin),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DynptrDataOrigin {
    slot: DynptrStackSlot,
    backing: DynptrBacking,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DynptrStackSlot {
    frame: usize,
    offset: i32,
}

fn stale_data_pointer_kind(
    context: &ProofSignalContext<'_>,
    state: &RegState,
    state_log_line: usize,
    reg: u8,
) -> Option<StaleDataPointerKind> {
    match state.reg_type.as_str() {
        "pkt" => Some(StaleDataPointerKind::Packet),
        "mem" | "rdonly_mem" => Some(StaleDataPointerKind::DynptrData(dynptr_data_origin(
            context,
            state_log_line,
            reg,
        )?)),
        _ => None,
    }
}

fn prior_dynptr_data_pointer_before_instruction(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: u8,
) -> Option<(DynptrDataOrigin, usize)> {
    context
        .branch_states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            if !matches!(reg_state.reg_type.as_str(), "mem" | "rdonly_mem") {
                return None;
            }
            if register_assigned_between(
                context.branch_states,
                context.log,
                reg,
                state.frame,
                fragment_start,
                state.log_line,
                instruction.line,
            ) {
                return None;
            }
            Some((
                dynptr_data_origin(context, state.log_line, reg)?,
                state.log_line,
            ))
        })
}

fn register_assigned_between(
    states: &[VerifierInsn],
    log: &str,
    reg: u8,
    frame: usize,
    fragment_start: usize,
    after_line: usize,
    before_line: usize,
) -> bool {
    instructions_in_line_range(log, after_line.saturating_add(1), before_line)
        .filter(|instruction| instruction_assigns_register(instruction.tail, reg))
        .any(|instruction| {
            instruction_frame(states, instruction, fragment_start)
                .is_none_or(|assigned_frame| assigned_frame == frame)
        })
}

fn instruction_frame(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> Option<usize> {
    latest_verifier_state_before_instruction(states, instruction, fragment_start)
        .map(|state| state.frame)
}

fn invalidating_helper_between(
    context: &ProofSignalContext<'_>,
    after_line: usize,
    before_line: usize,
    pointer_kind: StaleDataPointerKind,
) -> bool {
    if after_line >= before_line {
        return false;
    }
    instructions_in_line_range(context.log, after_line.saturating_add(1), before_line)
        .filter_map(|instruction| {
            let target = call_target_from_instruction_tail(instruction.tail)?;
            Some((instruction, target))
        })
        .any(|(instruction, target)| match pointer_kind {
            StaleDataPointerKind::Packet => packet_pointer_invalidating_helper(target),
            StaleDataPointerKind::DynptrData(origin) => {
                dynptr_data_invalidated_by_call(context, instruction, target, origin)
                    || (origin.backing == DynptrBacking::Packet
                        && packet_pointer_invalidating_helper(target))
            }
        })
}

fn packet_pointer_invalidating_helper(target: &str) -> bool {
    matches!(
        target,
        "bpf_xdp_adjust_head"
            | "bpf_xdp_adjust_meta"
            | "bpf_xdp_adjust_tail"
            | "bpf_skb_store_bytes"
            | "bpf_skb_pull_data"
            | "bpf_skb_change_head"
            | "bpf_skb_change_tail"
            | "bpf_skb_change_proto"
            | "bpf_skb_adjust_room"
            | "bpf_skb_vlan_push"
            | "bpf_skb_vlan_pop"
            | "bpf_l3_csum_replace"
            | "bpf_l4_csum_replace"
            | "bpf_lwt_push_encap"
            | "bpf_lwt_seg6_store_bytes"
            | "bpf_lwt_seg6_adjust_srh"
            | "bpf_lwt_seg6_action"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DynptrBacking {
    Packet,
    Memory,
}

fn dynptr_data_origin(
    context: &ProofSignalContext<'_>,
    before_line: usize,
    reg: u8,
) -> Option<DynptrDataOrigin> {
    let fragment_start = verifier_fragment_start_line(context.log, before_line);
    let mut current_reg = reg;
    let instructions =
        instructions_in_line_range(context.log, fragment_start, before_line.saturating_add(1))
            .collect::<Vec<_>>();
    for instruction in instructions.iter().rev().copied() {
        if let Some(source_reg) =
            instruction_single_register_rhs_source(instruction.tail, current_reg)
        {
            current_reg = source_reg;
            continue;
        }
        let target = call_target_from_instruction_tail(instruction.tail);
        if current_reg != 0 {
            continue;
        }
        let Some(target) = target else {
            continue;
        };
        let arg_reg = dynptr_data_producer_arg(target)?;
        let slot = dynptr_stack_slot_for_call_argument(
            context.branch_states,
            instruction,
            fragment_start,
            arg_reg,
        )?;
        let backing = dynptr_slot_backing_before(context, slot, instruction.line)?;
        return Some(DynptrDataOrigin { slot, backing });
    }
    None
}

fn dynptr_data_producer_arg(target: &str) -> Option<u8> {
    matches!(
        target,
        "bpf_dynptr_data" | "bpf_dynptr_slice" | "bpf_dynptr_slice_rdwr"
    )
    .then_some(1)
}

fn dynptr_slot_backing_before(
    context: &ProofSignalContext<'_>,
    slot: DynptrStackSlot,
    before_line: usize,
) -> Option<DynptrBacking> {
    let fragment_start = verifier_fragment_start_line(context.log, before_line);
    instructions_in_line_range(context.log, fragment_start, before_line)
        .filter_map(|instruction| {
            let target = call_target_from_instruction_tail(instruction.tail)?;
            let backing = dynptr_backing_from_helper(target)?;
            let arg_reg = dynptr_signal::dynptr_initializer_output_arg(target)?;
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

fn dynptr_data_invalidated_by_call(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    target: &str,
    origin: DynptrDataOrigin,
) -> bool {
    let Some(arg_reg) = dynptr_data_invalidating_arg(target) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    dynptr_stack_slot_for_call_argument(context.branch_states, instruction, fragment_start, arg_reg)
        == Some(origin.slot)
}

fn dynptr_data_invalidated_by_callback_write(
    context: &ProofSignalContext<'_>,
    after_line: usize,
    before_line: usize,
    origin: DynptrDataOrigin,
) -> bool {
    if after_line >= before_line {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, before_line);
    context
        .branch_states
        .iter()
        .filter(|state| state.log_line > after_line)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.callback_kind == Some(CallbackKind::Sync))
        .filter(|state| state.from_pc.is_some())
        .any(|entry| {
            bpf_loop_callback_entry_stack_pointer(context, fragment_start, entry).is_some_and(
                |data_slot| stack_pointer_can_reach_dynptr_slot(data_slot, origin.slot),
            ) && callback_writes_dynptr_slot(
                context,
                fragment_start,
                entry,
                before_line,
                origin.slot,
            )
        })
}

fn bpf_loop_callback_entry_stack_pointer(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    entry: &VerifierInsn,
) -> Option<DynptrStackSlot> {
    let from_pc = entry.from_pc?;
    let call_instruction =
        instruction_site_before_line(context.log, from_pc, fragment_start, entry.log_line)?;
    if call_target_from_instruction_tail(call_instruction.tail) != Some("bpf_loop") {
        return None;
    }
    let call_slot = dynptr_stack_slot_for_call_argument(
        context.branch_states,
        call_instruction,
        fragment_start,
        3,
    )?;
    let entry_slot = callback_entry_stack_slot(entry, 2)?;
    (call_slot == entry_slot).then_some(entry_slot)
}

fn stack_pointer_can_reach_dynptr_slot(pointer: DynptrStackSlot, slot: DynptrStackSlot) -> bool {
    if pointer.frame != slot.frame {
        return false;
    }
    let Some(slot_range) = dynptr_stack_slot_range(slot) else {
        return false;
    };
    i16::try_from(pointer.offset)
        .ok()
        .is_some_and(|offset| slot_range.contains(offset))
}

fn callback_entry_stack_slot(entry: &VerifierInsn, reg: u8) -> Option<DynptrStackSlot> {
    let reg_state = entry.regs.get(&reg)?;
    if reg_state.reg_type != "fp" || reg_state_has_variable_offset(reg_state) {
        return None;
    }
    Some(DynptrStackSlot {
        frame: reg_state.source_frame.unwrap_or(entry.frame),
        offset: reg_state.offset?,
    })
}

fn callback_writes_dynptr_slot(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    entry: &VerifierInsn,
    before_line: usize,
    slot: DynptrStackSlot,
) -> bool {
    let Some(slot_range) = dynptr_stack_slot_range(slot) else {
        return false;
    };
    instructions_in_line_range(context.log, entry.log_line.saturating_add(1), before_line)
        .filter(|instruction| memory_access_is_store(instruction.tail))
        .any(|instruction| {
            callback_instruction_matches_entry(
                context.branch_states,
                instruction,
                fragment_start,
                entry,
            ) && memory_store_overlaps_dynptr_slot(
                context.branch_states,
                instruction,
                fragment_start,
                slot,
                slot_range,
            )
        })
}

fn callback_instruction_matches_entry(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    entry: &VerifierInsn,
) -> bool {
    latest_verifier_state_before_instruction(states, instruction, fragment_start).is_some_and(
        |state| {
            state.log_line >= entry.log_line
                && state.frame == entry.frame
                && state.callback_kind == entry.callback_kind
        },
    )
}

fn memory_store_overlaps_dynptr_slot(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    slot: DynptrStackSlot,
    slot_range: StackByteRange,
) -> bool {
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    let Some((base, frame)) = latest_reg_state_before_instruction_with_frame(
        states,
        instruction,
        fragment_start,
        base_reg,
    ) else {
        return false;
    };
    if frame != slot.frame || base.reg_type != "fp" || reg_state_has_variable_offset(base) {
        return false;
    }
    stack_memory_access_range(base, instruction.tail)
        .is_some_and(|access| access.overlaps(slot_range))
}

fn stack_memory_access_range(base: &RegState, instruction_tail: &str) -> Option<StackByteRange> {
    let base_offset = i16::try_from(base.offset?).ok()?;
    let access_offset = i16::try_from(memory_access_offset(instruction_tail)?).ok()?;
    let start = base_offset.checked_add(access_offset)?;
    let width = i16::try_from(memory_access_width(instruction_tail)?).ok()?;
    stack_value_range(start, width)
}

fn dynptr_stack_slot_range(slot: DynptrStackSlot) -> Option<StackByteRange> {
    stack_value_range(i16::try_from(slot.offset).ok()?, 16)
}

fn dynptr_data_invalidating_arg(target: &str) -> Option<u8> {
    match target {
        "bpf_dynptr_write" => Some(1),
        "bpf_dynptr_from_mem" => Some(4),
        "bpf_dynptr_from_skb" | "bpf_dynptr_from_xdp" => Some(3),
        _ => None,
    }
}

fn dynptr_stack_slot_for_call_argument(
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

fn prohibited_pointer_arithmetic(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PointerProvenance {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("bitwise operator") || terminal.contains("pointer arithmetic")) {
        return false;
    }
    if terminal_mentions_pkt_end(&terminal) {
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
    if register_operands(instruction.tail).first().copied() != Some(reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
        .is_some_and(verifier_pointer_state_for_arithmetic)
}

fn verifier_pointer_state_for_arithmetic(state: &RegState) -> bool {
    state.reg_type != "scalar"
}

fn terminal_mentions_pkt_end(terminal: &str) -> bool {
    terminal.contains("pkt_end") || terminal.contains("ptr_to_packet_end")
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

fn stack_access_range_from_context(context: &ProofSignalContext<'_>) -> Option<StackByteRange> {
    stack_read_access_range(context.terminal_error)
        .or_else(|| terminal_stack_memory_access_range(context))
}

fn stack_read_access_range(message: &str) -> Option<StackByteRange> {
    message
        .to_ascii_lowercase()
        .contains("read from stack")
        .then(|| stack_access_range(message))
        .flatten()
}

fn terminal_stack_memory_access_range(context: &ProofSignalContext<'_>) -> Option<StackByteRange> {
    let instruction =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)?;
    if !memory_access_is_load(instruction.tail) {
        return None;
    }
    let width =
        terminal_instruction_access_width(context.log, context.terminal_pc, context.terminal_line)?;
    let insn_offset = terminal_instruction_memory_offset(
        context.log,
        context.terminal_pc,
        context.terminal_line,
    )?;
    let base_reg = memory_access_base_register(instruction.tail)?;
    let fragment_start = terminal_fragment_start(context, instruction);
    let base =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, base_reg)?;
    if base.reg_type != "fp" {
        return None;
    }
    let base_offset = i64::from(base.offset.unwrap_or(0));
    let start = base_offset.checked_add(insn_offset)?;
    let end = start.checked_add(i64::from(width))?;
    StackByteRange::new(i16::try_from(start).ok()?, i16::try_from(end).ok()?)
}

fn terminal_stack_memory_write_range_with_frame(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> Option<(StackByteRange, usize)> {
    if !memory_access_is_store(instruction.tail) {
        return None;
    }
    let width =
        terminal_instruction_access_width(context.log, context.terminal_pc, context.terminal_line)?;
    let insn_offset = terminal_instruction_memory_offset(
        context.log,
        context.terminal_pc,
        context.terminal_line,
    )?;
    let base_reg = memory_access_base_register(instruction.tail)?;
    let (base, frame) = latest_reg_state_before_instruction_with_frame(
        context.states,
        instruction,
        fragment_start,
        base_reg,
    )?;
    if base.reg_type != "fp" {
        return None;
    }
    let base_offset = i64::from(base.offset.unwrap_or(0));
    let start = base_offset.checked_add(insn_offset)?;
    let end = start.checked_add(i64::from(width))?;
    Some((
        StackByteRange::new(i16::try_from(start).ok()?, i16::try_from(end).ok()?)?,
        frame,
    ))
}

fn latest_reg_state_for_call_argument<'a>(
    states: &'a [VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
    terminal_line: Option<usize>,
    reg: u8,
) -> Option<&'a RegState> {
    latest_reg_state_for_call_argument_with_frame(
        states,
        instruction,
        fragment_start_line,
        terminal_line,
        reg,
    )
    .map(|(state, _)| state)
}

fn latest_reg_state_for_call_argument_with_frame<'a>(
    states: &'a [VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
    terminal_line: Option<usize>,
    reg: u8,
) -> Option<(&'a RegState, usize)> {
    let call_frame =
        latest_verifier_state_before_instruction(states, instruction, fragment_start_line)
            .map(|state| state.frame);
    latest_reg_state_before_instruction_with_frame(states, instruction, fragment_start_line, reg)
        .or_else(|| {
            states
                .iter()
                .filter(|state| state.log_line >= fragment_start_line)
                .filter(|state| terminal_line.is_none_or(|line| state.log_line < line))
                .filter(|state| state.pc <= instruction.pc)
                .filter(|state| call_frame.is_none_or(|frame| state.frame == frame))
                .rev()
                .find_map(|state| {
                    let reg_state = state.regs.get(&reg)?;
                    Some((reg_state, reg_state.source_frame.unwrap_or(state.frame)))
                })
        })
}

fn reg_state_has_variable_offset(state: &RegState) -> bool {
    state.tnum.is_some() || scalar_range_has_any_bound(state)
}

fn latest_stack_value_overlap(
    context: &ProofSignalContext<'_>,
    access: StackByteRange,
    target_size: i16,
    target_value: impl Fn(&RegState) -> bool,
) -> Option<bool> {
    latest_stack_slot_overlap(context, access, target_size, |stack| {
        stack.value.as_ref().is_some_and(&target_value)
    })
}

fn latest_stack_slot_overlap(
    context: &ProofSignalContext<'_>,
    access: StackByteRange,
    target_size: i16,
    target_slot: impl Fn(&StackState) -> bool,
) -> Option<bool> {
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(0);
    for state in context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| context.terminal_pc.is_none_or(|pc| state.pc <= pc))
        .filter(|state| {
            context
                .terminal_line
                .is_none_or(|line| state.log_line < line)
        })
        .rev()
    {
        let mut saw_overlap = false;
        let mut start_in_target = false;
        let mut start_in_non_target = false;
        let mut contains_target = false;
        for (offset, stack) in &state.stack {
            let is_target = target_slot(stack);
            let Some(range) = stack_value_range(*offset, if is_target { target_size } else { 8 })
            else {
                continue;
            };
            if !range.overlaps(access) {
                continue;
            }
            saw_overlap = true;
            if range.contains(access.start()) {
                if is_target {
                    start_in_target = true;
                } else {
                    start_in_non_target = true;
                }
            }
            if is_target && access.contains_range(range) {
                contains_target = true;
            }
        }
        if contains_target || start_in_target {
            return Some(true);
        }
        if start_in_non_target || saw_overlap {
            return Some(false);
        }
    }
    None
}

fn latest_live_ref_dynptr_stack_overlap_before_instruction(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    access: StackByteRange,
    frame: usize,
) -> Option<bool> {
    for state in context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .filter(|state| state.frame == frame)
        .rev()
    {
        let mut saw_overlap = false;
        let mut saw_live_ref_dynptr = false;
        for (offset, stack) in &state.stack {
            let is_live_ref_dynptr = dynptr_signal::dynptr_stack_slot_has_live_ref(stack, state);
            let is_dynptr = is_live_ref_dynptr
                || stack
                    .value
                    .as_ref()
                    .is_some_and(|value| value.reg_type.starts_with("dynptr"));
            let Some(range) = stack_value_range(*offset, if is_dynptr { 16 } else { 8 }) else {
                continue;
            };
            if !range.overlaps(access) {
                continue;
            }
            saw_overlap = true;
            if is_live_ref_dynptr {
                saw_live_ref_dynptr = true;
            }
        }
        if saw_live_ref_dynptr {
            return Some(true);
        }
        if saw_overlap {
            return Some(false);
        }
    }
    None
}

fn map_value_wide_access(
    log: &str,
    terminal_error: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    register: Option<u8>,
    states: &[VerifierInsn],
) -> bool {
    if !terminal_error.contains("invalid access to map value") {
        return false;
    }
    let Some(reg) = register else {
        return false;
    };
    let Some(reported_value_size) = parse_u32_after(terminal_error, "value_size=") else {
        return false;
    };
    let Some(access_size) = parse_u32_after(terminal_error, "size=") else {
        return false;
    };
    if access_size <= reported_value_size {
        return false;
    }
    if terminal_instruction_access_width(log, terminal_pc, terminal_line) != Some(access_size) {
        return false;
    }
    latest_reg_state_before(states, terminal_pc, reg).is_some_and(|state| {
        state.reg_type == "map_value" && state.map_value_size == Some(reported_value_size)
    })
}

fn map_value_checked_offset_relation_lost(
    terminal_error: &str,
    terminal_pc: Option<usize>,
    register: Option<u8>,
    states: &[VerifierInsn],
    events: &[ProofEvent],
    source_events: &[SourceEvent],
) -> bool {
    if !terminal_error.contains("invalid access to map value") {
        return false;
    }
    let Some(reg) = register else {
        return false;
    };
    let Some(reported_value_size) = parse_u32_after(terminal_error, "value_size=") else {
        return false;
    };
    let Some(access_offset) = parse_u32_after(terminal_error, "off=") else {
        return false;
    };
    let Some(access_size) = parse_u32_after(terminal_error, "size=") else {
        return false;
    };
    if access_size > reported_value_size {
        return false;
    }
    let Some(access_end) = access_offset.checked_add(access_size) else {
        return false;
    };
    if access_end <= reported_value_size {
        return false;
    }
    let Some(rejected) = rejected_source(events) else {
        return false;
    };
    if !source_guard_mentions_bound(events, source_events, reported_value_size, rejected) {
        return false;
    }
    latest_reg_state_before(states, terminal_pc, reg).is_some_and(|state| {
        state.reg_type == "map_value"
            && state.map_value_size == Some(reported_value_size)
            && map_value_range_may_exceed_value_size(state)
    })
}

fn map_value_guard_exceeds_value_size(context: &ProofSignalContext<'_>) -> bool {
    if !context
        .terminal_error
        .contains("invalid access to map value")
    {
        return false;
    }
    let Some(reg) = context.register else {
        return false;
    };
    let Some(value_size) = parse_u32_after(context.terminal_error, "value_size=") else {
        return false;
    };
    let Some(access_size) = parse_u32_after(context.terminal_error, "size=") else {
        return false;
    };
    if access_size > value_size {
        return false;
    }
    let Some(state) = latest_reg_state_before(context.states, context.terminal_pc, reg) else {
        return false;
    };
    if state.reg_type != "map_value" || state.map_value_size != Some(value_size) {
        return false;
    }
    let Some(access_offset) =
        terminal_instruction_memory_offset(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let state_offset = i64::from(state.offset.unwrap_or(0));
    let Some(total_fixed_offset) = state_offset.checked_add(access_offset) else {
        return false;
    };
    let Ok(total_fixed_offset) = u32::try_from(total_fixed_offset) else {
        return false;
    };
    let Some(bytes_after_field) = value_size.checked_sub(total_fixed_offset) else {
        return false;
    };
    let Some(max_index) = bytes_after_field.checked_sub(access_size) else {
        return false;
    };
    if map_value_variable_max_offset(state).is_none_or(|max| max <= u64::from(max_index)) {
        return false;
    }
    let Some(rejected) = rejected_source(context.events) else {
        return false;
    };
    let Some(index) = array_index_identifier(&rejected.text) else {
        return false;
    };
    source_guard_exceeds_index_capacity(context, rejected, &index, max_index, state, reg)
}

fn map_value_access_out_of_bounds(context: &ProofSignalContext<'_>) -> bool {
    if !context
        .terminal_error
        .contains("invalid access to map value")
    {
        return false;
    }
    let Some(value_size) = parse_u32_after(context.terminal_error, "value_size=") else {
        return false;
    };
    let Some(access_offset) = parse_u32_after(context.terminal_error, "off=") else {
        return false;
    };
    let Some(access_size) = parse_u32_after(context.terminal_error, "size=") else {
        return false;
    };
    if access_offset
        .checked_add(access_size)
        .is_none_or(|end| end <= value_size)
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let instruction_target = direct_call_target_from_instruction_tail(instruction.tail);
    let Some(reg) = memory_access_base_register(instruction.tail)
        .or_else(|| instruction_target.and_then(helper_memory_pointer_argument_register))
        .or(context.register)
        .or_else(|| register_from_terminal_error(context.terminal_error))
    else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    ) else {
        return false;
    };
    if state.reg_type != "map_value" || state.map_value_size != Some(value_size) {
        return false;
    }
    if let Some(base_reg) = memory_access_base_register(instruction.tail) {
        if access_size > value_size {
            return false;
        }
        return base_reg == reg
            && memory_access_width(instruction.tail) == Some(access_size)
            && map_value_terminal_offset_matches_state(
                state,
                access_offset,
                memory_access_offset(instruction.tail),
            );
    }
    let Some(target) = instruction_target else {
        return false;
    };
    helper_memory_pointer_argument_register(target) == Some(reg)
        && map_value_terminal_offset_matches_state(state, access_offset, Some(0))
        && helper_memory_access_length_matches(
            context.branch_states,
            instruction,
            fragment_start,
            target,
            access_size,
        )
}

fn map_value_terminal_offset_matches_state(
    state: &RegState,
    reported_offset: u32,
    instruction_offset: Option<i64>,
) -> bool {
    let Some(instruction_offset) = instruction_offset else {
        return false;
    };
    i64::from(state.offset.unwrap_or(0)).saturating_add(instruction_offset)
        == i64::from(reported_offset)
}

fn helper_memory_pointer_argument_register(target: &str) -> Option<u8> {
    match target {
        "bpf_probe_read"
        | "bpf_probe_read_kernel"
        | "bpf_probe_read_kernel_str"
        | "bpf_probe_read_user"
        | "bpf_probe_read_user_str" => Some(1),
        _ => None,
    }
}

fn helper_memory_access_length_matches(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
    access_size: u32,
) -> bool {
    let Some(length_reg) = scalar_length_helper_argument_register(target) else {
        return false;
    };
    latest_reg_state_before_instruction(states, instruction, fragment_start, length_reg)
        .is_some_and(|state| scalar_state_upper_bound_matches_size(state, access_size))
}

fn scalar_state_upper_bound_matches_size(state: &RegState, access_size: u32) -> bool {
    state.exact_value == Some(u64::from(access_size))
        || state.range.umax == Some(u64::from(access_size))
        || state
            .range
            .smax
            .is_some_and(|value| value == i64::from(access_size))
        || state.range.umax32 == Some(access_size)
        || state
            .range
            .smax32
            .is_some_and(|value| value == access_size as i32)
}

fn terminal_call_instruction_site<'a>(
    context: &'a ProofSignalContext<'a>,
) -> Option<TerminalInstruction<'a>> {
    terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line).or_else(
        || {
            nearest_call_instruction_before(
                context.log,
                context.terminal_line?,
                context.terminal_call_target,
            )
        },
    )
}

fn nearest_call_instruction_before<'a>(
    log: &'a str,
    terminal_line: usize,
    expected_target: Option<&'a str>,
) -> Option<TerminalInstruction<'a>> {
    let lines = log.lines().collect::<Vec<_>>();
    let mut idx = terminal_line.saturating_sub(1).min(lines.len());
    while idx > 0 {
        let next_line_toward_terminal = lines.get(idx).map(|line| line.trim());
        idx -= 1;
        let line = lines[idx].trim();
        if is_call_search_boundary(line, next_line_toward_terminal) {
            return None;
        }
        let Some((pc, tail)) = parse_instruction_line(line) else {
            continue;
        };
        let Some(target) = call_target_from_instruction_tail(tail) else {
            continue;
        };
        if expected_target.is_some_and(|expected| expected != target) {
            continue;
        }
        return Some(TerminalInstruction {
            pc,
            line: idx + 1,
            tail,
        });
    }
    None
}

fn is_call_search_boundary(line: &str, next_line_toward_terminal: Option<&str>) -> bool {
    line.starts_with("func#")
        || line.contains("-- BEGIN PROG LOAD LOG --")
        || line.contains("-- END PROG LOAD LOG --")
        || line.starts_with("processed ")
        || line.starts_with("verification time ")
        || line.starts_with("stack depth ")
        || (is_verifier_error_line(line)
            && !is_dynptr_call_detail_line(line, next_line_toward_terminal))
}

fn is_dynptr_call_detail_line(line: &str, next_line_toward_terminal: Option<&str>) -> bool {
    let lower = line.to_ascii_lowercase();
    (is_dynptr_stack_slot_detail_line(&lower)
        && next_line_toward_terminal.is_some_and(is_dynptr_contract_terminal_line))
        || (lower.contains("unbounded memory access")
            && lower.contains("var")
            && next_line_toward_terminal.is_some_and(is_memory_len_pair_error_line))
}

fn is_dynptr_stack_slot_detail_line(lower: &str) -> bool {
    lower.contains("cannot pass in dynptr at an offset")
        || lower.contains("dynptr has to be at a constant offset")
        || lower.contains("expected pointer to stack or const struct bpf_dynptr")
}

fn is_dynptr_contract_terminal_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("expected an initialized dynptr")
        || lower.contains("dynptr has to be an uninitialized dynptr")
}

fn is_memory_len_pair_error_line(line: &str) -> bool {
    line.to_ascii_lowercase()
        .contains("memory, len pair leads to invalid memory access")
}

fn terminal_error_has_nearby_prior_line(
    log: &str,
    terminal_error: &str,
    lookback: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let lines = log.lines().collect::<Vec<_>>();
    lines.iter().enumerate().any(|(idx, line)| {
        line.contains(terminal_error)
            && lines[idx.saturating_sub(lookback)..idx]
                .iter()
                .any(|prior| predicate(prior))
    })
}

fn stack_alignment_lowering_signal(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::Alignment {
        return false;
    }
    let Some(reported_size) = misaligned_stack_access_size(context.terminal_error) else {
        return false;
    };
    if reported_size == 0 {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if memory_access_width(instruction.tail) != Some(reported_size) {
        return false;
    }
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    let Some(access_offset) = memory_access_offset(instruction.tail) else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(base_state) =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, base_reg)
    else {
        return false;
    };
    if base_state.reg_type != "fp" {
        return false;
    }
    let total_offset = i64::from(base_state.offset.unwrap_or(0)).saturating_add(access_offset);
    total_offset.rem_euclid(i64::from(reported_size)) != 0
}

fn atomic_memory_alignment_scalar_base(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::Alignment {
        return false;
    }
    let Some(reported_size) = misaligned_access_size(context.terminal_error) else {
        return false;
    };
    if reported_size == 0 {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !memory_access_is_atomic(instruction.tail) {
        return false;
    }
    if atomic_memory_access_width(instruction.tail) != Some(reported_size) {
        return false;
    }
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(base_state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        base_reg,
    )
    .or_else(|| {
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, base_reg)
    }) else {
        return false;
    };
    base_state.reg_type == "scalar"
}

fn loop_back_edge_state_repeats(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::LoopBound {
        return false;
    }
    let Some((current, previous)) = terminal_loop_state_pair(context) else {
        return false;
    };
    loop_state_snapshots_repeat(&current, &previous)
}

fn terminal_loop_state_pair(
    context: &ProofSignalContext<'_>,
) -> Option<(VerifierInsn, VerifierInsn)> {
    let pc = parse_u32_after(context.terminal_error, "insn ")? as usize;
    let lines = context.log.lines().collect::<Vec<_>>();
    let terminal_idx = context
        .terminal_line
        .map(|line| line.saturating_sub(1))
        .or_else(|| {
            lines
                .iter()
                .position(|line| line.contains(context.terminal_error))
        })?;
    let mut current = None;
    let mut previous = None;
    for line in &lines[terminal_idx.saturating_add(1)..] {
        let trimmed = line.trim();
        if let Some(state_text) = trimmed.strip_prefix("cur state:") {
            current = parse_loop_state_snapshot(pc, state_text.trim());
        } else if let Some(state_text) = trimmed.strip_prefix("old state:") {
            previous = parse_loop_state_snapshot(pc, state_text.trim());
        } else if is_verifier_fragment_boundary(trimmed) {
            break;
        }
        if current.is_some() && previous.is_some() {
            break;
        }
    }
    current.zip(previous)
}

fn parse_loop_state_snapshot(pc: usize, state_text: &str) -> Option<VerifierInsn> {
    let state_text = normalize_loop_state_register_access_suffixes(state_text);
    let pseudo_log = format!("{pc}: {state_text}");
    verifier_states_with_branch_deltas_from_log(&pseudo_log)
        .ok()?
        .into_iter()
        .next()
}

fn normalize_loop_state_register_access_suffixes(state_text: &str) -> String {
    state_text
        .split_whitespace()
        .map(|token| {
            let Some((lhs, rhs)) = token.split_once('=') else {
                return token.to_string();
            };
            let Some(normalized) = normalize_register_state_lhs(lhs) else {
                return token.to_string();
            };
            format!("{normalized}={rhs}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_register_state_lhs(lhs: &str) -> Option<String> {
    let rest = lhs.strip_prefix('R')?;
    let digits_len = rest.chars().take_while(|ch| ch.is_ascii_digit()).count();
    if digits_len == 0 {
        return None;
    }
    let suffix = &rest[digits_len..];
    matches!(suffix, "" | "_w" | "_r" | "_rw").then(|| format!("R{}", &rest[..digits_len]))
}

fn loop_state_snapshots_repeat(current: &VerifierInsn, previous: &VerifierInsn) -> bool {
    if current.frame != previous.frame
        || current.refs != previous.refs
        || current.ref_ids != previous.ref_ids
        || current.callback_kind != previous.callback_kind
        || current.callback != previous.callback
    {
        return false;
    }

    let current_reg_count = current.regs.keys().filter(|reg| **reg != 10).count();
    let previous_reg_count = previous.regs.keys().filter(|reg| **reg != 10).count();
    if current_reg_count != previous_reg_count {
        return false;
    }
    for (reg, state) in current.regs.iter().filter(|(reg, _)| **reg != 10) {
        let Some(old) = previous.regs.get(reg) else {
            return false;
        };
        if !loop_reg_state_repeats(state, old) {
            return false;
        }
    }

    if current.stack.len() != previous.stack.len() {
        return false;
    }
    for (off, state) in &current.stack {
        let Some(old) = previous.stack.get(off) else {
            return false;
        };
        if !loop_stack_state_repeats(state, old) {
            return false;
        }
    }

    current_reg_count >= 2 || (current_reg_count >= 1 && !current.stack.is_empty())
}

fn loop_reg_state_repeats(current: &RegState, previous: &RegState) -> bool {
    current.reg_type == previous.reg_type
        && current.value_width == previous.value_width
        && current.precise == previous.precise
        && current.exact_value == previous.exact_value
        && current.tnum == previous.tnum
        && current.range == previous.range
        && current.packet_range == previous.packet_range
        && current.map_value_size == previous.map_value_size
        && current.mem_size == previous.mem_size
        && current.offset == previous.offset
        && current.source_frame == previous.source_frame
        && current.id == previous.id
        && current.ref_id == previous.ref_id
}

fn loop_stack_state_repeats(current: &StackState, previous: &StackState) -> bool {
    current.slot_types == previous.slot_types
        && match (&current.value, &previous.value) {
            (Some(current), Some(previous)) => loop_reg_state_repeats(current, previous),
            (None, None) => true,
            _ => false,
        }
}

fn pointer_shift_lowering_signal(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PointerProvenance {
        return false;
    }
    if !context
        .terminal_error
        .contains("pointer arithmetic with <<=")
    {
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
    if !instruction.tail.contains(&format!("r{reg} <<=")) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
        .is_some_and(is_pointer_state)
}

fn modified_context_pointer_lowering_signal(context: &ProofSignalContext<'_>) -> bool {
    if !context
        .terminal_error
        .contains("dereference of modified ctx ptr")
    {
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
    if memory_access_base_register(instruction.tail) != Some(reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(state) =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
    else {
        return false;
    };
    if state.reg_type != "ctx" || state.offset.unwrap_or(0) == 0 {
        return false;
    }
    let Some(offset) = parse_u32_after(context.terminal_error, "off=") else {
        return false;
    };
    u32::try_from(state.offset.unwrap_or(0)) == Ok(offset)
}

fn shared_instruction_pointer_merge_signal(context: &ProofSignalContext<'_>) -> bool {
    if !context
        .terminal_error
        .contains("same insn cannot be used with different pointers")
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(current) =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, base_reg)
    else {
        return false;
    };
    if !is_pointer_state(current) {
        return false;
    }
    context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc == instruction.pc)
        .filter_map(|state| state.regs.get(&base_reg))
        .filter(|state| is_pointer_state(state))
        .any(|state| state.reg_type != current.reg_type)
}

fn subprogram_context_argument_dropped_signal(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("expects pointer to ctx")
        || !terminal.contains("caller passes invalid args into func")
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !instruction.tail.contains("call pc+") {
        return false;
    }
    let Some(callee) = invalid_args_function_name(context.terminal_error) else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(rejected) = source_for_instruction_in_fragment(
        context.source_events,
        instruction.pc,
        fragment_start,
        instruction.line,
    ) else {
        return false;
    };
    if call_argument(&rejected.text, callee, 0).as_deref() != Some("ctx") {
        return false;
    }
    let Some(current_r1) =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, 1)
    else {
        return false;
    };
    if current_r1.reg_type == "ctx" {
        return false;
    }
    context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter_map(|state| state.regs.get(&1))
        .any(|state| state.reg_type == "ctx")
}

fn source_for_instruction_in_fragment(
    source_events: &[SourceEvent],
    pc: usize,
    fragment_start_line: usize,
    instruction_line: usize,
) -> Option<&SourceLocation> {
    source_events
        .iter()
        .filter(|event| event.log_line >= fragment_start_line)
        .filter(|event| event.log_line < instruction_line)
        .filter(|event| event.pc.is_some_and(|event_pc| event_pc <= pc))
        .max_by_key(|event| (event.pc.unwrap_or(0), event.log_line))
        .map(|event| &event.source)
}

fn misaligned_stack_access_size(message: &str) -> Option<u32> {
    message
        .contains("misaligned stack access")
        .then(|| parse_u32_after(message, "size ").or_else(|| parse_u32_after(message, "size=")))
        .flatten()
}

fn misaligned_access_size(message: &str) -> Option<u32> {
    message
        .contains("misaligned access")
        .then(|| parse_u32_after(message, "size ").or_else(|| parse_u32_after(message, "size=")))
        .flatten()
}

fn parse_signed_decimal(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    text.parse().ok()
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

fn packet_range_proof_lost_before_access(events: &[ProofEvent]) -> bool {
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

fn packet_guard_undercovers_access(context: &ProofSignalContext<'_>) -> bool {
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

fn packet_access_without_bounds_proof(context: &ProofSignalContext<'_>) -> bool {
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

fn packet_verifier_precision_signal(context: &ProofSignalContext<'_>) -> Option<ProofSignal> {
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

fn guard_branch_packet_operand_registers(
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

fn rejected_source(events: &[ProofEvent]) -> Option<&SourceLocation> {
    events
        .iter()
        .find(|event| event.role == ProofEventRole::Rejected)
        .and_then(|event| event.source.as_ref())
}

fn source_for_pc_in_rejected_file(
    source_events: &[SourceEvent],
    pc: usize,
    rejected: Option<&SourceLocation>,
) -> Option<SourceLocation> {
    let rejected = rejected?;
    let source = source_events
        .iter()
        .filter(|event| event.source.path == rejected.path)
        .filter(|event| event.pc.is_some_and(|event_pc| event_pc <= pc))
        .max_by_key(|event| event.pc)?
        .source
        .clone();
    (!same_source_location(&source, rejected)).then_some(source)
}

fn same_source_location(left: &SourceLocation, right: &SourceLocation) -> bool {
    left.path == right.path && left.line == right.line && left.text == right.text
}

fn source_guard_mentions_bound(
    events: &[ProofEvent],
    source_events: &[SourceEvent],
    bound: u32,
    rejected: &SourceLocation,
) -> bool {
    events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::SourceComment
            && event.obligation == ProofObligation::ScalarRange
            && event.source.as_ref().is_some_and(|source| {
                looks_like_scalar_guard(&source.text)
                    && text_has_numeric_token(&source.text, bound)
                    && source_guard_has_structural_link(source_events, source, rejected)
            })
    })
}

fn source_guard_exceeds_index_capacity(
    context: &ProofSignalContext<'_>,
    rejected: &SourceLocation,
    index: &str,
    max_index: u32,
    current: &RegState,
    map_reg: u8,
) -> bool {
    context.events.iter().any(|event| {
        if event.role != ProofEventRole::ProofEstablished
            || event.evidence != ProofEventEvidence::SourceComment
            || event.obligation != ProofObligation::ScalarRange
        {
            return false;
        }
        let Some(source) = event.source.as_ref() else {
            return false;
        };
        if source.path != rejected.path
            || source.line >= rejected.line
            || !looks_like_scalar_guard(&source.text)
            || scalar_guard_upper_bound_for_identifier(&source.text, index)
                .is_none_or(|upper| upper <= max_index)
        {
            return false;
        }
        let Some(guard_pc) = event.pc else {
            return false;
        };
        if context
            .terminal_pc
            .is_none_or(|terminal_pc| guard_pc >= terminal_pc)
        {
            return false;
        }
        let Some(guard_log_line) = source_event_log_line(
            context.source_events,
            source,
            event.pc,
            context.terminal_line,
        ) else {
            return false;
        };
        if context
            .terminal_line
            .is_none_or(|terminal_line| guard_log_line >= terminal_line)
        {
            return false;
        }
        scalar_guard_verifier_state_links_to_map_value(
            context,
            guard_pc,
            guard_log_line,
            map_reg,
            current,
        )
    })
}

fn source_event_log_line(
    source_events: &[SourceEvent],
    source: &SourceLocation,
    pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<usize> {
    source_events
        .iter()
        .filter(|event| same_source_location(&event.source, source))
        .filter(|event| event.pc == pc)
        .filter(|event| terminal_line.is_none_or(|terminal_line| event.log_line < terminal_line))
        .map(|event| event.log_line)
        .max()
}

fn scalar_guard_verifier_state_links_to_map_value(
    context: &ProofSignalContext<'_>,
    guard_pc: usize,
    guard_log_line: usize,
    map_reg: u8,
    current: &RegState,
) -> bool {
    context
        .branch_states
        .iter()
        .filter(|state| state.pc >= guard_pc && state.pc <= guard_pc.saturating_add(3))
        .filter(|state| state.log_line > guard_log_line)
        .filter(|state| {
            context
                .terminal_line
                .is_none_or(|terminal_line| state.log_line < terminal_line)
        })
        .any(|state| {
            let Some(instruction) = instruction_on_log_line(context.log, state.log_line) else {
                return false;
            };
            if instruction.pc != state.pc {
                return false;
            }
            let regs = conditional_branch_registers(instruction.tail);
            regs.iter().any(|reg| {
                state.regs.get(reg).is_some_and(|guard| {
                    guard.reg_type == "scalar"
                        && scalar_ranges_match(guard, current)
                        && map_value_add_uses_scalar_between(
                            context.log,
                            guard_pc,
                            guard_log_line,
                            context.terminal_pc,
                            context.terminal_line,
                            map_reg,
                            *reg,
                        )
                })
            })
        })
}

fn map_value_add_uses_scalar_between(
    log: &str,
    guard_pc: usize,
    guard_log_line: usize,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    map_reg: u8,
    scalar_reg: u8,
) -> bool {
    let Some(terminal_pc) = terminal_pc else {
        return false;
    };
    if guard_pc >= terminal_pc {
        return false;
    }
    let before_line = terminal_line.unwrap_or(usize::MAX);
    instructions_in_line_range(log, guard_log_line.saturating_add(1), before_line).any(
        |instruction| {
            instruction.pc > guard_pc
                && instruction.pc < terminal_pc
                && instruction_adds_register(instruction.tail, map_reg, scalar_reg)
        },
    )
}

fn register_from_terminal_error(message: &str) -> Option<u8> {
    let bytes = message.as_bytes();
    let mut idx = 0usize;
    while idx + 1 < bytes.len() {
        if bytes[idx] != b'R' || !bytes[idx + 1].is_ascii_digit() {
            idx += 1;
            continue;
        }
        let start = idx + 1;
        let mut end = start + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        return message[start..end].parse().ok();
    }
    None
}

fn source_guard_has_structural_link(
    source_events: &[SourceEvent],
    guard: &SourceLocation,
    rejected: &SourceLocation,
) -> bool {
    let guard_ids = identifier_tokens(&guard.text);
    let rejected_ids = identifier_tokens(&rejected.text);
    let common = guard_ids
        .iter()
        .filter(|identifier| rejected_ids.iter().any(|rejected| rejected == *identifier))
        .count();
    if common >= 2 {
        return true;
    }
    source_events.iter().any(|event| {
        event.source.path == guard.path
            && event.source.line > guard.line
            && event.source.line < rejected.line
            && source_line_links_identifiers(&event.source.text, &guard_ids, &rejected_ids)
    })
}

fn source_line_links_identifiers(
    text: &str,
    guard_ids: &[String],
    rejected_ids: &[String],
) -> bool {
    if !(text.starts_with("for ") || text.starts_with("if ")) {
        return false;
    }
    let ids = identifier_tokens(text);
    ids.iter()
        .any(|identifier| guard_ids.iter().any(|guard| guard == identifier))
        && ids
            .iter()
            .any(|identifier| rejected_ids.iter().any(|rejected| rejected == identifier))
}

fn array_index_identifier(text: &str) -> Option<String> {
    let start = text.rfind('[')?;
    let end = text[start + 1..].find(']')? + start + 1;
    let index = text[start + 1..end].trim();
    is_bare_identifier_argument(index).then(|| index.to_string())
}

fn scalar_guard_upper_bound_for_identifier(text: &str, identifier: &str) -> Option<u32> {
    let condition = text
        .trim()
        .strip_prefix("if")
        .map(str::trim)
        .unwrap_or(text.trim());
    let condition = trim_outer_parens(condition);
    condition
        .split("&&")
        .filter_map(|clause| simple_upper_bound_clause(clause, identifier))
        .min()
}

fn simple_upper_bound_clause(clause: &str, identifier: &str) -> Option<u32> {
    for op in ["<=", ">=", "<", ">"] {
        let Some((left, right)) = clause.split_once(op) else {
            continue;
        };
        let left = trim_outer_parens(left.trim());
        let right = trim_outer_parens(right.trim());
        if left == identifier {
            let value = parse_u32_literal(right)?;
            return match op {
                "<" => value.checked_sub(1),
                "<=" => Some(value),
                _ => None,
            };
        }
        if right == identifier {
            let value = parse_u32_literal(left)?;
            return match op {
                ">" => value.checked_sub(1),
                ">=" => Some(value),
                _ => None,
            };
        }
    }
    None
}

fn trim_outer_parens(text: &str) -> &str {
    let mut text = text.trim();
    loop {
        let Some(inner) = text
            .strip_prefix('(')
            .and_then(|text| text.strip_suffix(')'))
        else {
            return text;
        };
        text = inner.trim();
    }
}

fn parse_u32_literal(text: &str) -> Option<u32> {
    let digits = text.trim().trim_end_matches(['u', 'U', 'l', 'L']);
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

fn first_call_argument(source_text: &str, function: &str) -> Option<String> {
    call_argument(source_text, function, 0)
}

fn invalid_args_function_name(terminal_error: &str) -> Option<&str> {
    let (_, after_open) = terminal_error.rsplit_once("('")?;
    let (name, _) = after_open.split_once("')")?;
    (!name.is_empty()).then_some(name)
}

fn call_argument(source_text: &str, function: &str, argument_index: usize) -> Option<String> {
    let open = source_text.find(function)? + function.len();
    let mut chars = source_text[open..].char_indices();
    let (_, first) = chars.next()?;
    if first != '(' {
        return None;
    }
    let args_start = open + first.len_utf8();
    let mut arg_start = args_start;
    let mut current_argument = 0usize;
    let mut depth = 0usize;
    for (relative_idx, ch) in chars {
        let absolute_idx = open + relative_idx;
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => {
                return (current_argument == argument_index)
                    .then(|| source_text[arg_start..absolute_idx].trim().to_string())
            }
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                if current_argument == argument_index {
                    return Some(source_text[arg_start..absolute_idx].trim().to_string());
                }
                current_argument += 1;
                arg_start = absolute_idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    None
}

fn is_bare_identifier_argument(argument: &str) -> bool {
    let argument = argument.trim();
    let mut chars = argument.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_literal_null_argument(argument: &str) -> bool {
    let normalized = argument
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if matches!(normalized.as_str(), "null" | "(void*)null") {
        return true;
    }
    let suffixless_zero = normalized.trim_end_matches(['u', 'l']) == "0";
    suffixless_zero
        || matches!(normalized.as_str(), "(void*)0")
        || (normalized.starts_with('(')
            && (normalized.ends_with(")0") || normalized.ends_with(")null"))
            && normalized.contains('*'))
}

fn map_argument_has_relocation_proof(
    argument: &str,
    rejected: &SourceLocation,
    source_events: &[SourceEvent],
) -> bool {
    if is_literal_null_argument(argument) {
        return false;
    }
    // Corpus reconstructions use this explicit marker when the original report
    // loaded raw instructions and lost the map relocation before verification.
    if is_reconstructed_missing_relocation_argument(argument) {
        return true;
    }
    let Some(symbol) = addressed_identifier(argument) else {
        return false;
    };
    source_has_map_symbol_declaration(source_events, rejected, &symbol)
}

fn is_reconstructed_missing_relocation_argument(argument: &str) -> bool {
    identifier_tokens(argument)
        .iter()
        .any(|identifier| identifier == "missing_relocation")
}

fn addressed_identifier(argument: &str) -> Option<String> {
    let ampersand = argument.rfind('&')?;
    let prefix = argument[..ampersand].trim();
    if !(prefix.is_empty() || prefix.ends_with(')')) {
        return None;
    }
    let rest = argument[ampersand + 1..].trim_start();
    let ident_len = rest
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if ident_len == 0 {
        return None;
    }
    if !rest[ident_len..].trim().is_empty() {
        return None;
    }
    Some(rest[..ident_len].to_string())
}

fn source_has_map_symbol_declaration(
    source_events: &[SourceEvent],
    rejected: &SourceLocation,
    symbol: &str,
) -> bool {
    source_events.iter().any(|event| {
        event.source.path == rejected.path
            && event.source.line <= rejected.line
            && source_line_declares_map_symbol(&event.source.text, symbol)
    })
}

fn source_line_declares_map_symbol(text: &str, symbol: &str) -> bool {
    if !identifier_tokens(text)
        .iter()
        .any(|identifier| identifier == symbol)
    {
        return false;
    }
    let compact = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    compact.contains("sec(\".maps\")")
        || compact.contains("sec(\"maps\")")
        || compact.contains("__section(\".maps\")")
        || compact.contains("__section(\"maps\")")
}

fn text_has_numeric_token(text: &str, expected: u32) -> bool {
    numeric_tokens(text)
        .into_iter()
        .any(|token| token == expected)
}

fn max_numeric_token(text: &str) -> Option<u32> {
    numeric_tokens(text).into_iter().max()
}

fn numeric_tokens(text: &str) -> Vec<u32> {
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    let mut tokens = Vec::new();
    while idx < bytes.len() {
        if !bytes[idx].is_ascii_digit() {
            idx += 1;
            continue;
        }
        let start = idx;
        idx += 1;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if let Ok(value) = text[start..idx].parse::<u32>() {
            tokens.push(value);
        }
    }
    tokens
}

fn identifier_tokens(text: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut start = None;
    for (idx, ch) in text.char_indices() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            start.get_or_insert(idx);
            continue;
        }
        if let Some(token_start) = start.take() {
            push_meaningful_identifier(&mut identifiers, &text[token_start..idx]);
        }
    }
    if let Some(token_start) = start {
        push_meaningful_identifier(&mut identifiers, &text[token_start..]);
    }
    identifiers
}

fn push_meaningful_identifier(identifiers: &mut Vec<String>, token: &str) {
    if (token.len() < 2 && !matches!(token, "i" | "j" | "k"))
        || token.as_bytes()[0].is_ascii_digit()
        || matches!(
            token,
            "if" | "void"
                | "char"
                | "unsigned"
                | "int"
                | "__u8"
                | "__u16"
                | "__u32"
                | "__u64"
                | "data"
                | "data_end"
                | "byte"
        )
    {
        return;
    }
    identifiers.push(token.to_string());
}

fn looks_like_packet_pointer_derivation(text: &str) -> bool {
    let text = text.trim();
    if text.starts_with("if ") || !text.contains('=') || !text.contains('+') {
        return false;
    }
    let Some((lhs, _)) = text.split_once('=') else {
        return false;
    };
    lhs.contains('*')
}

fn verifier_precision_signal(context: &ProofSignalContext<'_>) -> Option<ProofSignal> {
    match context.obligation {
        ProofObligation::ScalarRange if map_value_relation_precision_boundary(context) => {
            Some(ProofSignal::MapValueRelationPrecisionBoundary)
        }
        _ => None,
    }
}

fn map_value_relation_precision_boundary(context: &ProofSignalContext<'_>) -> bool {
    if !context
        .terminal_error
        .contains("invalid access to map value")
    {
        return false;
    }
    let Some(value_size) = parse_u32_after(context.terminal_error, "value_size=") else {
        return false;
    };
    let Some(access_offset) = parse_u32_after(context.terminal_error, "off=") else {
        return false;
    };
    let Some(access_size) = parse_u32_after(context.terminal_error, "size=") else {
        return false;
    };
    if access_offset
        .checked_add(access_size)
        .is_none_or(|end| end <= value_size)
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(target) = direct_call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(pointer_reg) = helper_memory_pointer_argument_register(target) else {
        return false;
    };
    let Some(length_reg) = scalar_length_helper_argument_register(target) else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(pointer_state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        pointer_reg,
    ) else {
        return false;
    };
    if pointer_state.reg_type != "map_value" || pointer_state.map_value_size != Some(value_size) {
        return false;
    }
    let Some(relation_capacity) = map_value_remaining_capacity(pointer_state, value_size) else {
        return false;
    };
    if !map_value_relation_precision_source_shape(
        context,
        instruction,
        fragment_start,
        length_reg,
        relation_capacity,
    ) {
        return false;
    }
    if map_value_access_range_may_exceed_value_size(pointer_state, access_size) {
        return true;
    }
    latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        length_reg,
    )
    .is_some_and(|state| {
        access_size > value_size && scalar_state_upper_bound_matches_size(state, access_size)
    })
}

fn map_value_relation_precision_source_shape(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    length_reg: u8,
    relation_capacity: u32,
) -> bool {
    let helper_call_is_visible = source_text_contains_any(context.events, &["bpf_probe_read"])
        || source_event_text_contains_any(context.source_events, &["bpf_probe_read"]);
    if !helper_call_is_visible {
        return false;
    }
    if !source_text_contains_any(
        context.events,
        &[
            " min,",
            "&event->content[event->len]",
            "&event->payload[total_len]",
        ],
    ) {
        return false;
    }
    (source_event_text_contains_min_clamp(context.source_events)
        && recent_scalar_state_at_most(
            context.branch_states,
            instruction,
            fragment_start,
            Some(length_reg),
            relation_capacity,
        ))
        || source_event_text_contains_relation_guard(
            context.source_events,
            context.branch_states,
            instruction,
            fragment_start,
            length_reg,
            relation_capacity,
        )
        || source_event_text_contains_split_payload_bounds(
            context.source_events,
            context.branch_states,
            instruction,
            fragment_start,
            length_reg,
            relation_capacity,
        )
}

fn source_event_text_contains_any(source_events: &[SourceEvent], needles: &[&str]) -> bool {
    source_events.iter().any(|event| {
        needles
            .iter()
            .any(|needle| event.source.text.contains(needle))
    })
}

fn source_event_text_contains_min_clamp(source_events: &[SourceEvent]) -> bool {
    source_events.iter().any(|event| {
        let text = event.source.text.as_str();
        text.contains("MIN(") || text.contains("min =")
    })
}

fn source_event_text_contains_relation_guard(
    source_events: &[SourceEvent],
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    length_reg: u8,
    relation_capacity: u32,
) -> bool {
    source_events.iter().any(|event| {
        let text = event.source.text.as_str();
        text.contains("if (")
            && text.contains('+')
            && (text.contains(" < ") || text.contains(" <= "))
            && (source_line_numeric_bound_at_most(text, relation_capacity)
                || recent_scalar_state_at_most(
                    states,
                    instruction,
                    fragment_start,
                    Some(length_reg),
                    relation_capacity,
                ))
    })
}

fn source_event_text_contains_split_payload_bounds(
    source_events: &[SourceEvent],
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    length_reg: u8,
    relation_capacity: u32,
) -> bool {
    let has_total_len_guard = source_events.iter().any(|event| {
        let text = event.source.text.as_str();
        text.contains("if (")
            && text.contains("total_len")
            && (text.contains(" <")
                || text.contains(" <=")
                || text.contains(" >")
                || text.contains(" >="))
    });
    let has_to_read_guard = source_events.iter().any(|event| {
        let text = event.source.text.as_str();
        text.contains("if (")
            && text.contains("to_read")
            && (text.contains(" <")
                || text.contains(" <=")
                || text.contains(" >")
                || text.contains(" >="))
    });
    has_total_len_guard
        && has_to_read_guard
        && recent_scalar_state_at_most(
            states,
            instruction,
            fragment_start,
            Some(length_reg),
            relation_capacity,
        )
}

fn source_line_numeric_bound_at_most(text: &str, relation_capacity: u32) -> bool {
    max_numeric_token(text).is_some_and(|bound| bound <= relation_capacity)
}

fn recent_scalar_state_at_most(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: Option<u8>,
    relation_capacity: u32,
) -> bool {
    let earliest_pc = instruction.pc.saturating_sub(12);
    states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc >= earliest_pc && state.pc <= instruction.pc)
        .any(|state| match reg {
            Some(reg) => state
                .regs
                .get(&reg)
                .is_some_and(|state| scalar_state_upper_bound_at_most(state, relation_capacity)),
            None => state
                .regs
                .values()
                .any(|state| scalar_state_upper_bound_at_most(state, relation_capacity)),
        })
}

fn source_text_contains(events: &[ProofEvent], predicate: impl Fn(&str) -> bool) -> bool {
    events
        .iter()
        .filter_map(|event| event.source.as_ref())
        .any(|source| predicate(&source.text))
}

fn source_text_contains_any(events: &[ProofEvent], needles: &[&str]) -> bool {
    source_text_contains(events, |text| {
        let text = text.to_ascii_lowercase();
        needles.iter().any(|needle| text.contains(needle))
    })
}

fn memory_object_access_out_of_bounds(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::ScalarRange {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("invalid access to memory") || !terminal.contains("mem_size=") {
        return false;
    }
    let Some(mem_size) = parse_u32_after(context.terminal_error, "mem_size=") else {
        return false;
    };
    let Some(access_offset) = parse_i64_after(context.terminal_error, "off=") else {
        return false;
    };
    let Some(access_size) = parse_u32_after(context.terminal_error, "size=") else {
        return false;
    };
    if !byte_range_out_of_bounds(access_offset, access_size, mem_size) {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if memory_access_width(instruction.tail) != Some(access_size) {
        return false;
    }
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    if context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
        .is_some_and(|reg| reg != base_reg)
    {
        return false;
    }
    let Some(instruction_offset) = memory_access_offset(instruction.tail) else {
        return false;
    };
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(base_state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        base_reg,
    ) else {
        return false;
    };
    if !memory_object_state_matches_size(base_state, mem_size) {
        return false;
    }
    let total_offset = i64::from(base_state.offset.unwrap_or(0)).saturating_add(instruction_offset);
    total_offset == access_offset && byte_range_out_of_bounds(total_offset, access_size, mem_size)
}

fn memory_object_state_matches_size(state: &RegState, mem_size: u32) -> bool {
    state.mem_size == Some(mem_size)
        && (state.reg_type == "mem" || state.reg_type.ends_with("_mem"))
}

fn byte_range_out_of_bounds(offset: i64, size: u32, limit: u32) -> bool {
    offset < 0
        || offset
            .checked_add(i64::from(size))
            .is_none_or(|end| end > i64::from(limit))
}

fn return_range_out_of_bounds(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::ScalarRange {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("at program exit")
        || !terminal.contains("register r")
        || !terminal.contains("should have been in")
    {
        return false;
    }
    let Some(required_range) = terminal_required_return_range(context.terminal_error) else {
        return false;
    };
    let reg = context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
        .unwrap_or(0);
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !instruction_is_bpf_exit(instruction.tail) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    latest_reg_state_at_or_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    )
    .or_else(|| {
        latest_reg_state_before_instruction(context.branch_states, instruction, fragment_start, reg)
    })
    .is_some_and(|state| scalar_state_outside_required_range(state, required_range))
}

fn stack_variable_offset_out_of_bounds(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::ScalarRange {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("unbounded variable-offset") || !terminal.contains("stack") {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(width) = memory_access_width(instruction.tail) else {
        return false;
    };
    let Some(instruction_offset) = memory_access_offset(instruction.tail) else {
        return false;
    };
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    if context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
        .is_some_and(|reg| reg != base_reg)
    {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some(base_state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        base_reg,
    ) else {
        return false;
    };
    stack_pointer_access_range_out_of_bounds(base_state, instruction_offset, width)
}

fn stack_pointer_access_range_out_of_bounds(
    state: &RegState,
    instruction_offset: i64,
    width: u32,
) -> bool {
    if state.reg_type != "fp" || (state.tnum.is_none() && !scalar_range_has_any_bound(state)) {
        return false;
    }
    let base_offset = i64::from(state.offset.unwrap_or(0));
    let min_offset = scalar_range_min_i64(state);
    let max_offset = scalar_range_max_i64(state);
    let width = i64::from(width);
    let min_byte = min_offset.and_then(|offset| {
        base_offset
            .checked_add(offset)
            .and_then(|value| value.checked_add(instruction_offset))
    });
    let max_byte_exclusive = max_offset.and_then(|offset| {
        base_offset
            .checked_add(offset)
            .and_then(|value| value.checked_add(instruction_offset))
            .and_then(|value| value.checked_add(width))
    });
    min_byte.is_none_or(|start| start < i64::from(-MAX_BPF_STACK_DEPTH))
        || max_byte_exclusive.is_none_or(|end| end > 0)
}

fn scalar_range_unsafe_at_use(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::ScalarRange {
        return false;
    }
    if !scalar_range_terminal_needs_runtime_bound(context.terminal_error) {
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
    if !instruction_consumes_scalar_register(instruction.tail, reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
        .is_some_and(|state| scalar_range_state_is_unsafe_for_signal(state, context.terminal_error))
}

fn scalar_range_terminal_needs_runtime_bound(terminal_error: &str) -> bool {
    let terminal = terminal_error.to_ascii_lowercase();
    !terminal.contains("program exit")
        && [
            "min value is negative",
            "zero-sized",
            "unbounded variable-offset",
            "unbounded memory access",
            "math between",
            "invalid access to map value",
            "invalid access to memory",
            "pointer be out of bounds",
            "outside of the allowed memory range",
        ]
        .iter()
        .any(|needle| terminal.contains(needle))
}

fn instruction_consumes_scalar_register(instruction_tail: &str, reg: u8) -> bool {
    let opcode_tail = instruction_tail
        .split_once(';')
        .map(|(opcode, _)| opcode)
        .unwrap_or(instruction_tail);
    if let Some(target) = direct_call_target_from_instruction_tail(opcode_tail) {
        return helper_consumes_scalar_length_register(target, reg);
    }
    instruction_reads_register(opcode_tail, reg)
}

fn helper_consumes_scalar_length_register(target: &str, reg: u8) -> bool {
    scalar_length_helper_argument_register(target) == Some(reg)
        || matches!(target, "bpf_csum_diff") && matches!(reg, 2 | 4)
}

fn scalar_length_helper_argument_register(target: &str) -> Option<u8> {
    match target {
        "bpf_probe_read"
        | "bpf_probe_read_kernel"
        | "bpf_probe_read_kernel_str"
        | "bpf_probe_read_user"
        | "bpf_probe_read_user_str" => Some(2),
        "bpf_csum_diff" => Some(4),
        "bpf_skb_load_bytes" => Some(4),
        "bpf_perf_event_output" => Some(5),
        _ => None,
    }
}

fn scalar_range_state_is_unsafe_for_signal(state: &RegState, terminal_error: &str) -> bool {
    let terminal = terminal_error.to_ascii_lowercase();
    if terminal.contains("zero-sized") {
        return scalar_range_may_include_zero(state);
    }
    if let Some(value) = state.exact_value {
        return value > i32::MAX as u64;
    }
    if map_value_range_may_exceed_value_size(state) {
        return true;
    }
    if state.reg_type != "scalar" && !scalar_range_has_any_bound(state) {
        return false;
    }
    scalar_range_may_be_negative(state) || scalar_range_upper_unbounded_or_too_large(state)
}

#[cfg(test)]
mod tests;
