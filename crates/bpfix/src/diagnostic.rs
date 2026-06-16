use anyhow::Result;
use bpfanalysis::verifier_log::{
    verifier_states_with_branch_deltas_from_log, VerifierInsn, VerifierInsnKind,
};

use crate::family::ProofObligation;
use crate::proof::{instantiate_required_proof, RequiredProof};
use crate::source::{collect_source_events, terminal_source, SourceEvent, SourceLocation};

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

mod callback_signal;
mod context_signal;
mod dynptr_signal;
mod fallback_pointer_signal;
mod helper_contract_signal;
mod irq_signal;
mod iterator_signal;
mod lowering_signal;
mod map_value_signal;
mod nullable_signal;
mod opaque_pointer_signal;
mod packet_signal;
mod proof_events;
mod protocol_signal;
mod scalar_range_signal;
mod shared;
mod signal;
mod signal_pipeline;
mod source_query;
mod stack_access;
mod stack_signal;
mod stale_pointer_signal;
mod type_contract_signal;
use shared::{
    dynptr_slot_backing_before, dynptr_stack_slot_for_call_argument, is_pointer_state,
    latest_reg_state_before_instruction_with_origin, latest_reg_state_for_call_argument,
    latest_reg_state_for_call_argument_with_frame, latest_register_assignment,
    register_from_terminal_error, terminal_call_instruction_site,
    terminal_error_has_nearby_prior_line, terminal_fragment_start, DynptrBacking, DynptrStackSlot,
};
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
            events.extend(proof_events::pointer_provenance_events(
                &states,
                &source_events,
                terminal_pc,
                rejected_source.as_ref(),
                register,
            ));
        }
        ProofObligation::PacketBounds => events.extend(proof_events::packet_bounds_events(
            &proof_events::PacketBoundsEventContext {
                log,
                states: &states,
                branch_states: &branch_states,
                source_events: &source_events,
                terminal_pc,
                terminal_error,
                rejected_source: rejected_source.as_ref(),
                register,
            },
        )),
        ProofObligation::ScalarRange => events.extend(proof_events::scalar_range_events(
            &states,
            &source_events,
            terminal_pc,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::NullablePointer => events.extend(proof_events::nullable_pointer_events(
            &states,
            &source_events,
            terminal_pc,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::StackInitialized => events.extend(proof_events::stack_initialized_events(
            &source_events,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::ReferenceLifecycle => {
            events.extend(proof_events::reference_lifecycle_events(
                &source_events,
                rejected_source.as_ref(),
                register,
            ))
        }
        ProofObligation::EnvironmentCapability => {
            events.extend(proof_events::environment_capability_events(
                &source_events,
                rejected_source.as_ref(),
                register,
            ))
        }
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
    let signals = signal_pipeline::proof_signals(signal_context);

    Ok(VerifierLogAnalysis {
        state_count: states.len(),
        required_proof,
        events,
        signals,
    })
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

#[cfg(test)]
mod tests;
