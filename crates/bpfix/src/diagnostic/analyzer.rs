use anyhow::Result;
use bpfanalysis::verifier_log::{verifier_states_with_branch_deltas_from_log, VerifierInsnKind};

use crate::family::ProofObligation;
use crate::proof::instantiate_required_proof;
use crate::source::{collect_source_events, terminal_source};

use super::model::{ProofSignalContext, VerifierLogAnalysis, VerifierLogContext};
use super::{proof_events, signal_pipeline, ProofEvent, ProofEventEvidence, ProofEventRole};

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
