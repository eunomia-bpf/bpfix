use bpfanalysis::verifier_log::VerifierInsn;

use crate::family::ProofObligation;
use crate::proof::RequiredProof;
use crate::source::{SourceEvent, SourceLocation};

use super::signal::ProofSignal;

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

pub(super) struct ProofSignalContext<'a> {
    pub(super) log: &'a str,
    pub(super) full_log: &'a str,
    pub(super) object_sections: &'a [String],
    pub(super) terminal_error: &'a str,
    pub(super) terminal_call_target: Option<&'a str>,
    pub(super) obligation: ProofObligation,
    pub(super) terminal_pc: Option<usize>,
    pub(super) terminal_line: Option<usize>,
    pub(super) register: Option<u8>,
    pub(super) states: &'a [VerifierInsn],
    pub(super) branch_states: &'a [VerifierInsn],
    pub(super) source_events: &'a [SourceEvent],
    pub(super) events: &'a [ProofEvent],
}
