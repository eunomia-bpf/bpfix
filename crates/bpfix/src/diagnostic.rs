use anyhow::Result;
use bpfanalysis::{
    verifier_states_with_branch_deltas_from_log, RegState, VerifierInsn, VerifierInsnKind,
};

use crate::family::ProofObligation;
use crate::proof::{
    instantiate_required_proof, packet_required_range, verifier_value_summary, RequiredProof,
};
use crate::source::{
    collect_source_events, latest_source_before, looks_like_null_check, looks_like_nullable_return,
    looks_like_packet_bounds_check, looks_like_reference_acquire, looks_like_reference_release,
    looks_like_scalar_guard, looks_like_stack_initialization, source_for_pc, terminal_source,
    SourceEvent, SourceLocation,
};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSignal {
    WideStackAlignment,
    SharedInstructionPointerMerge,
    SharedInstructionPathProofLoss,
    Alu32PointerCopyDropsProvenance,
    ConstantScalarMemoryLoad,
    SharedInstructionUninitializedRegister,
    PointerShiftDropsProvenance,
    ModifiedContextPointer,
    SubprogramContextArgumentDropped,
    PacketPointerProofLostAfterBoundsCheck,
    PacketRangeProofLostBeforeAccess,
    MapValueWideAccess,
    MapValueCheckedOffsetRelationLost,
    MapPointerArgumentScalarZero,
    ContextAccessSourceArgumentMismatch,
    PacketMaxOffsetPrecisionBoundary,
    MapValueRelationPrecisionBoundary,
}

impl ProofSignal {
    pub(crate) const fn failure_class(self) -> &'static str {
        if self.is_source_state_signal() {
            "source_bug"
        } else if self.is_verifier_precision_boundary() {
            "verifier_false_positive"
        } else {
            "lowering_artifact"
        }
    }

    pub(crate) const fn summary(self) -> &'static str {
        match self {
            Self::MapPointerArgumentScalarZero => {
                "helper map-pointer argument is scalar zero at the verifier rejection"
            }
            Self::ContextAccessSourceArgumentMismatch => {
                "tracing context argument type does not match the verifier-visible function signature"
            }
            signal if signal.is_verifier_precision_boundary() => {
                "verifier precision limit may hide an existing safety proof"
            }
            _ => "verifier-visible compiler lowering hides the required proof",
        }
    }

    pub(crate) const fn help_safety(self) -> &'static str {
        if matches!(self, Self::MapPointerArgumentScalarZero)
            || self.is_verifier_precision_boundary()
        {
            "triage_only"
        } else {
            "repair_hint"
        }
    }

    pub(crate) const fn evidence_kind(self) -> &'static str {
        if self.is_source_state_signal() {
            "verifier_state_signal"
        } else if self.is_verifier_precision_boundary() {
            "verifier_precision_signal"
        } else {
            "lowering_artifact_signal"
        }
    }

    pub(crate) const fn evidence_detail(self) -> &'static str {
        match self {
            Self::WideStackAlignment => {
                "compiler-lowered stack access requires stronger alignment than the source layout exposes"
            }
            Self::SharedInstructionPointerMerge => {
                "compiler code merging hides distinct pointer proofs from the verifier"
            }
            Self::SharedInstructionPathProofLoss => {
                "one verifier path reaches this shared instruction with a valid pointer proof, but another path reaches it after the proof is clobbered"
            }
            Self::Alu32PointerCopyDropsProvenance => {
                "a 32-bit register copy materializes a packet pointer as a scalar and drops verifier pointer provenance"
            }
            Self::ConstantScalarMemoryLoad => {
                "bytecode tries to dereference a small scalar constant, which is a compiler or relocation lowering shape rather than a verifier-tracked pointer"
            }
            Self::SharedInstructionUninitializedRegister => {
                "one verifier path initializes this register before a shared instruction, but another path reaches the same instruction without that register proof"
            }
            Self::PointerShiftDropsProvenance => {
                "compiler-lowered integer operation drops pointer provenance"
            }
            Self::ModifiedContextPointer => {
                "compiler-lowered context access violates the verifier context contract"
            }
            Self::SubprogramContextArgumentDropped => {
                "compiler liveness hides the context argument required by a BPF subprogram"
            }
            Self::PacketPointerProofLostAfterBoundsCheck => {
                "compiler-lowered control flow hides an established packet-pointer proof"
            }
            Self::PacketRangeProofLostBeforeAccess => {
                "verifier state proves the packet access range earlier, but the rejected path reaches the access after that range proof is lost"
            }
            Self::MapValueWideAccess => {
                "bytecode performs a map-value access wider than the verifier-proven map value size"
            }
            Self::MapValueCheckedOffsetRelationLost => {
                "source bounds the map-value expression to the declared value size, but verifier state later sees the rebuilt pointer range cross that size"
            }
            Self::MapPointerArgumentScalarZero => {
                "helper expects a map pointer, but verifier state shows scalar zero in the map argument register at the helper call"
            }
            Self::ContextAccessSourceArgumentMismatch => {
                "verifier reports the traced-function argument at this context slot as PTR rather than a directly supported struct pointer, while the rejected source is a BPF_PROG argument load from the raw tracing context"
            }
            Self::PacketMaxOffsetPrecisionBoundary => {
                "verifier state reaches a packet access with a large variable offset range at the packet-offset precision boundary"
            }
            Self::MapValueRelationPrecisionBoundary => {
                "source-level map-value bounds guard is present, but the verifier appears to lose a cross-variable range relation"
            }
        }
    }

    pub(crate) const fn help(self) -> &'static str {
        match self {
            Self::WideStackAlignment => {
                "wide stack loads, stores, copies, or inline assembly can make stack-object alignment a verifier-visible property; align the stack object or avoid the wide access shape."
            }
            Self::SharedInstructionPointerMerge => {
                "Keep incompatible pointer-typed paths separated at the dereference, or force the load to stay branch-local so one instruction is not shared by different verifier pointer types."
            }
            Self::SharedInstructionPathProofLoss => {
                "Keep the checked pointer use on the path where the pointer proof is established, or split the shared instruction so the clobbered path cannot reach it."
            }
            Self::Alu32PointerCopyDropsProvenance => {
                "Keep packet pointers in 64-bit verifier-tracked registers; avoid 32-bit moves or ALU32 lowering for pointer values before packet access."
            }
            Self::ConstantScalarMemoryLoad => {
                "Rebuild the object with verifier-friendly optimization and relocation settings so field offsets are folded into recognized pointer accesses instead of standalone scalar dereferences."
            }
            Self::SharedInstructionUninitializedRegister => {
                "Initialize the register on every path before the shared instruction, or keep the path-specific spill/load separate so the verifier can see the initialized value."
            }
            Self::PointerShiftDropsProvenance => {
                "Keep packet or context pointers in verifier-tracked 64-bit pointer values; avoid materializing them through 32-bit scalar arithmetic before the access."
            }
            Self::ModifiedContextPointer => {
                "Keep context field accesses as verifier-recognized field loads; avoid wide casts or modified context pointers for adjacent fields."
            }
            Self::SubprogramContextArgumentDropped => {
                "Keep the context argument verifier-visible at the BPF-to-BPF callsite, for example by passing it directly or preventing the compiler from dropping the value."
            }
            Self::PacketPointerProofLostAfterBoundsCheck => {
                "Keep the checked packet pointer derivation in the same verifier-visible path as the dereference, or rederive it from a checked base immediately before use."
            }
            Self::PacketRangeProofLostBeforeAccess => {
                "Keep the packet pointer that received the sufficient data_end range proof live through the access, or recheck the final derived pointer immediately before dereferencing it."
            }
            Self::MapValueWideAccess => {
                "Keep generated or lowered map-value loads and stores within the declared value type width; avoid widening a 32-bit value access into a 64-bit BPF memory operation."
            }
            Self::MapValueCheckedOffsetRelationLost => {
                "Reuse the exact bounded map-value address expression at the access site, or store the checked remaining capacity in one scalar that the final load uses directly."
            }
            Self::MapPointerArgumentScalarZero => {
                "Pass a verifier-visible map pointer as the helper's map argument. If the source names a map but the verifier still sees zero, inspect the loader/object path and ensure map relocations are applied before loading raw instructions."
            }
            Self::ContextAccessSourceArgumentMismatch => {
                "Use only fentry arguments whose BTF type is verifier-supported at this slot, or avoid reading this argument through BPF_PROG when the traced function exposes it as an unsupported pointer type."
            }
            Self::PacketMaxOffsetPrecisionBoundary => {
                "Treat this as a verifier precision boundary: clamp the packet cursor to a verifier-friendly maximum before the loop, then rederive and recheck the exact byte pointer used by the load."
            }
            Self::MapValueRelationPrecisionBoundary => {
                "Make the remaining map-value capacity explicit in one bounded variable, clamp the helper length to that variable, and pass that same value to the helper."
            }
        }
    }

    pub(crate) const fn confidence(self) -> &'static str {
        "medium"
    }

    const fn selection_rank(self) -> u8 {
        match self {
            Self::WideStackAlignment
            | Self::SharedInstructionPointerMerge
            | Self::PointerShiftDropsProvenance
            | Self::ModifiedContextPointer
            | Self::SubprogramContextArgumentDropped => 20,
            signal if signal.is_source_state_signal() => 10,
            signal if signal.is_verifier_precision_boundary() => 30,
            _ => 10,
        }
    }

    const fn is_verifier_precision_boundary(self) -> bool {
        matches!(
            self,
            Self::PacketMaxOffsetPrecisionBoundary | Self::MapValueRelationPrecisionBoundary
        )
    }

    const fn is_source_state_signal(self) -> bool {
        matches!(
            self,
            Self::MapPointerArgumentScalarZero | Self::ContextAccessSourceArgumentMismatch
        )
    }

    pub(crate) fn can_override_base_failure_class(self, base_failure_class: &str) -> bool {
        base_failure_class == "source_bug"
            || (base_failure_class == "environment_or_configuration"
                && matches!(self, Self::ContextAccessSourceArgumentMismatch))
    }

    pub(crate) const fn replaces_classifier_help(self) -> bool {
        matches!(self, Self::ContextAccessSourceArgumentMismatch)
    }
}

pub fn analyze_verifier_log(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_error: &str,
    obligation: ProofObligation,
) -> Result<VerifierLogAnalysis> {
    let branch_states = verifier_states_with_branch_deltas_from_log(log)?;
    let states = branch_states
        .iter()
        .filter(|state| state.kind != VerifierInsnKind::BranchDeltaState)
        .cloned()
        .collect::<Vec<_>>();
    let source_events = collect_source_events(log);
    let required_proof =
        instantiate_required_proof(terminal_error, terminal_pc, &states, obligation);
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
        ProofObligation::PacketBounds => events.extend(packet_bounds_events(
            &states,
            &source_events,
            terminal_pc,
            terminal_error,
            rejected_source.as_ref(),
            register,
        )),
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
        terminal_error,
        obligation,
        terminal_pc,
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

fn packet_bounds_events(
    states: &[VerifierInsn],
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
    terminal_error: &str,
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_packet_bounds_check(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            evidence: ProofEventEvidence::SourceComment,
            obligation: ProofObligation::PacketBounds,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "packet bounds proof is established by this data_end check".to_string(),
        });
    }
    if let Some((pc, range, required)) =
        latest_sufficient_packet_range(states, terminal_pc, terminal_error, register)
    {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            evidence: ProofEventEvidence::VerifierState,
            obligation: ProofObligation::PacketBounds,
            pc: Some(pc),
            source: source_for_pc(source_events, pc).cloned(),
            register,
            detail: format!(
                "verifier had proved packet range {range} bytes here, enough for the required {required} bytes"
            ),
        });
        if let Some((pc, current_range)) =
            packet_range_lost_before_access(states, terminal_pc, terminal_error, register, pc)
        {
            events.push(ProofEvent {
                role: ProofEventRole::ProofLost,
                evidence: ProofEventEvidence::VerifierState,
                obligation: ProofObligation::PacketBounds,
                pc: Some(pc),
                source: source_for_pc(source_events, pc).cloned(),
                register,
                detail: format!(
                    "verifier packet range for this register dropped to {current_range} bytes before the rejected access"
                ),
            });
        }
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
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc < pc))
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            if reg_state.reg_type != "pkt" {
                return None;
            }
            let range = reg_state.packet_range?;
            (range >= required).then_some((state.pc, range, required))
        })
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
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .filter(|state| state.pc > proof_pc)
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            if reg_state.reg_type != "pkt" {
                return None;
            }
            let range = reg_state.packet_range?;
            (range < required).then_some((state.pc, range))
        })
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
    terminal_error: &'a str,
    obligation: ProofObligation,
    terminal_pc: Option<usize>,
    register: Option<u8>,
    states: &'a [VerifierInsn],
    branch_states: &'a [VerifierInsn],
    source_events: &'a [SourceEvent],
    events: &'a [ProofEvent],
}

fn proof_signals(context: ProofSignalContext<'_>) -> Vec<ProofSignal> {
    let mut signals = Vec::new();
    if let Some(signal) = terminal_lowering_signal(context.terminal_error) {
        signals.push(signal);
    }
    if context.source_events.is_empty() {
        if let Some(signal) = bytecode_only_lowering_signal(
            context.log,
            context.terminal_error,
            context.obligation,
            context.terminal_pc,
            context.register,
            context.states,
        ) {
            signals.push(signal);
        }
    }
    if let Some(signal) = verifier_precision_signal(context.obligation, context.events) {
        signals.push(signal);
    }
    if let Some(signal) = packet_verifier_precision_signal(&context) {
        signals.push(signal);
    }
    if context_access_source_argument_mismatch(
        context.log,
        context.terminal_error,
        context.terminal_pc,
        context.states,
        context.events,
    ) {
        signals.push(ProofSignal::ContextAccessSourceArgumentMismatch);
    }
    if map_pointer_argument_scalar_zero(
        context.log,
        context.terminal_error,
        context.terminal_pc,
        context.register,
        context.states,
        context.events,
    ) {
        signals.push(ProofSignal::MapPointerArgumentScalarZero);
    }
    if context
        .events
        .iter()
        .any(packet_proof_lost_after_bounds_check)
    {
        signals.push(ProofSignal::PacketPointerProofLostAfterBoundsCheck);
    }
    if packet_range_proof_lost_before_access(context.events) {
        signals.push(ProofSignal::PacketRangeProofLostBeforeAccess);
    }
    if map_value_wide_access(
        context.log,
        context.terminal_error,
        context.terminal_pc,
        context.register,
        context.branch_states,
    ) {
        signals.push(ProofSignal::MapValueWideAccess);
    }
    if map_value_checked_offset_relation_lost(
        context.terminal_error,
        context.terminal_pc,
        context.register,
        context.states,
        context.events,
        context.source_events,
    ) {
        signals.push(ProofSignal::MapValueCheckedOffsetRelationLost);
    }
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

fn context_access_source_argument_mismatch(
    log: &str,
    terminal_error: &str,
    terminal_pc: Option<usize>,
    states: &[VerifierInsn],
    events: &[ProofEvent],
) -> bool {
    let terminal = terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid bpf_context access")
        || terminal.contains("invalid ctx access")
        || terminal.contains("invalid access to context"))
    {
        return false;
    }
    if !terminal_error_has_nearby_prior_line(log, terminal_error, 3, |line| {
        line.contains("type PTR is not a struct")
    }) {
        return false;
    }
    let Some(rejected) = rejected_source(events) else {
        return false;
    };
    if !rejected.text.contains("BPF_PROG(") {
        return false;
    }
    latest_reg_state_before(states, terminal_pc, 1).is_some_and(|state| state.reg_type == "ctx")
}

fn map_pointer_argument_scalar_zero(
    log: &str,
    terminal_error: &str,
    terminal_pc: Option<usize>,
    register: Option<u8>,
    states: &[VerifierInsn],
    events: &[ProofEvent],
) -> bool {
    if !terminal_error.contains("expected=map_ptr") {
        return false;
    }
    let Some(reg) = register else {
        return false;
    };
    if reg != 1 {
        return false;
    }
    if !terminal_instruction_contains(log, terminal_pc, "call bpf_map_lookup_elem#") {
        return false;
    }
    let Some(rejected) = rejected_source(events) else {
        return false;
    };
    if !rejected.text.contains("bpf_map_lookup_elem") {
        return false;
    }
    if first_call_argument(&rejected.text, "bpf_map_lookup_elem")
        .as_deref()
        .is_some_and(is_literal_null_argument)
    {
        return false;
    }
    let Some(state) = latest_reg_state_before(states, terminal_pc, reg) else {
        return false;
    };
    state.reg_type == "scalar" && state.exact_value == Some(0)
}

fn map_value_wide_access(
    log: &str,
    terminal_error: &str,
    terminal_pc: Option<usize>,
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
    if terminal_instruction_access_width(log, terminal_pc) != Some(access_size) {
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

fn terminal_instruction_access_width(log: &str, terminal_pc: Option<usize>) -> Option<u32> {
    let pc = terminal_pc?;
    let prefix = format!("{pc}:");
    log.lines()
        .filter_map(|line| line.trim().strip_prefix(&prefix))
        .find_map(memory_access_width)
}

fn terminal_instruction_contains(log: &str, terminal_pc: Option<usize>, needle: &str) -> bool {
    let Some(pc) = terminal_pc else {
        return false;
    };
    let prefix = format!("{pc}:");
    log.lines()
        .filter_map(|line| line.trim().strip_prefix(&prefix))
        .any(|line| line.contains(needle))
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

fn memory_access_width(line_after_pc: &str) -> Option<u32> {
    let marker = "*(u";
    let start = line_after_pc.find(marker)? + marker.len();
    let bytes = line_after_pc.as_bytes();
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if line_after_pc.get(end..end + 3)? != " *)" {
        return None;
    }
    line_after_pc[start..end]
        .parse::<u32>()
        .ok()
        .and_then(|bits| bits.checked_div(8))
}

fn parse_u32_after(message: &str, needle: &str) -> Option<u32> {
    let bytes = message.as_bytes();
    let mut search_start = 0usize;
    while let Some(relative) = message[search_start..].find(needle) {
        let field_start = search_start + relative;
        if field_start > 0 {
            let previous = bytes[field_start - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' {
                search_start = field_start + needle.len();
                continue;
            }
        }
        let start = field_start + needle.len();
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > start {
            return message[start..end].parse().ok();
        }
        search_start = field_start + needle.len();
    }
    None
}

fn latest_reg_state_before(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<&RegState> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .filter_map(|state| state.regs.get(&reg))
        .next()
}

fn terminal_lowering_signal(message: &str) -> Option<ProofSignal> {
    let message = message.to_ascii_lowercase();
    if message.contains("misaligned stack access") {
        Some(ProofSignal::WideStackAlignment)
    } else if message.contains("same insn cannot be used with different pointers") {
        Some(ProofSignal::SharedInstructionPointerMerge)
    } else if message.contains("pointer arithmetic with <<=") {
        Some(ProofSignal::PointerShiftDropsProvenance)
    } else if message.contains("dereference of modified ctx ptr") {
        Some(ProofSignal::ModifiedContextPointer)
    } else if message.contains("expects pointer to ctx")
        && message.contains("caller passes invalid args into func")
    {
        Some(ProofSignal::SubprogramContextArgumentDropped)
    } else {
        None
    }
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
            && event
                .source
                .as_ref()
                .is_some_and(|source| looks_like_packet_pointer_derivation(&source.text))
    });
    has_sufficient_range
        && events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost
                && event.evidence == ProofEventEvidence::VerifierState
                && event.obligation == ProofObligation::PacketBounds
        })
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
        && (packet_source_guard_covers_required_range(context.events, required)
            || has_prior_sufficient_packet_range_for_rejected_source(context.events))
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

fn packet_source_guard_covers_required_range(events: &[ProofEvent], required: u32) -> bool {
    events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::SourceComment
            && event.obligation == ProofObligation::PacketBounds
            && event.source.as_ref().is_some_and(|source| {
                looks_like_packet_bounds_check(&source.text)
                    && (max_numeric_token(&source.text).is_some_and(|guarded| guarded >= required)
                        || source.text.contains("sizeof("))
            })
    })
}

fn rejected_source(events: &[ProofEvent]) -> Option<&SourceLocation> {
    events
        .iter()
        .find(|event| event.role == ProofEventRole::Rejected)
        .and_then(|event| event.source.as_ref())
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

fn first_call_argument(source_text: &str, function: &str) -> Option<String> {
    let open = source_text.find(function)? + function.len();
    let mut chars = source_text[open..].char_indices();
    let (_, first) = chars.next()?;
    if first != '(' {
        return None;
    }
    let args_start = open + first.len_utf8();
    let mut depth = 0usize;
    for (relative_idx, ch) in chars {
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => {
                return Some(
                    source_text[args_start..open + relative_idx]
                        .trim()
                        .to_string(),
                )
            }
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                return Some(
                    source_text[args_start..open + relative_idx]
                        .trim()
                        .to_string(),
                )
            }
            _ => {}
        }
    }
    None
}

fn is_literal_null_argument(argument: &str) -> bool {
    let normalized = argument
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "0" | "null" | "(void*)0" | "(void*)null"
    )
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

fn verifier_precision_signal(
    obligation: ProofObligation,
    events: &[ProofEvent],
) -> Option<ProofSignal> {
    match obligation {
        ProofObligation::ScalarRange
            if source_text_contains_any(events, &["bpf_probe_read"])
                && source_text_contains_any(
                    events,
                    &[
                        " min,",
                        "&event->content[event->len]",
                        "&event->payload[total_len]",
                    ],
                ) =>
        {
            Some(ProofSignal::MapValueRelationPrecisionBoundary)
        }
        _ => None,
    }
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

fn latest_unsafe_scalar_state(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<(usize, &RegState)> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            ((reg_state.reg_type == "scalar" && scalar_range_is_unsafe(reg_state))
                || map_value_range_may_exceed_value_size(reg_state))
            .then_some((state.pc, reg_state))
        })
}

fn map_value_range_may_exceed_value_size(state: &RegState) -> bool {
    if state.reg_type != "map_value" {
        return false;
    }
    let Some(value_size) = state.map_value_size else {
        return false;
    };
    let max_variable_offset = state
        .range
        .umax
        .or_else(|| state.range.smax.and_then(|value| u64::try_from(value).ok()));
    let fixed_offset = state.offset.and_then(|offset| u64::try_from(offset).ok());
    let max_offset = match (fixed_offset, max_variable_offset) {
        (Some(fixed), Some(variable)) => fixed.checked_add(variable),
        (Some(fixed), None) => Some(fixed),
        (None, Some(variable)) => Some(variable),
        (None, None) => None,
    };
    max_offset.is_some_and(|offset| offset >= u64::from(value_size))
}

fn latest_nullable_state(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<(usize, String)> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            reg_state
                .reg_type
                .contains("_or_null")
                .then(|| (state.pc, reg_state.reg_type.clone()))
        })
}

fn scalar_range_is_unsafe(state: &RegState) -> bool {
    state.range.smin.is_none_or(|value| value < 0)
        || state.range.umin.is_none()
        || state.range.umax.is_none_or(|value| value > i32::MAX as u64)
}

#[cfg(test)]
mod tests {
    use super::{analyze_verifier_log, ProofEventEvidence, ProofEventRole};
    use crate::family::ProofObligation;

    #[test]
    fn branch_merge_case_produces_proof_lifecycle_events() {
        let log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(37),
            "R5 invalid mem access 'scalar'",
            ProofObligation::PointerProvenance,
        )
        .unwrap();

        assert_eq!(analysis.state_count, 60);
        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::PointerProvenance
        );
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 263
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofEstablished
                && event.source.as_ref().unwrap().line == 267
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost
                && event.evidence == ProofEventEvidence::VerifierState
                && event.source.as_ref().unwrap().line == 267
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 270
        }));
    }

    #[test]
    fn scalar_range_case_identifies_obligation_and_rejection() {
        let log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(33),
            "value -2147483648 makes pkt pointer be out of bounds",
            ProofObligation::ScalarRange,
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::ScalarRange
        );
        assert!(analysis
            .required_proof
            .description
            .contains("cannot be negative"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 274
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 280
        }));
    }

    #[test]
    fn map_value_access_case_describes_value_size_bounds() {
        let log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-78196801/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(13),
            "invalid access to map value, value_size=24 off=67 size=1; R0 max value is outside of the allowed memory range",
            ProofObligation::ScalarRange,
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::ScalarRange
        );
        assert!(analysis.required_proof.description.contains("map-value"));
        assert!(analysis
            .required_proof
            .description
            .contains("value_size=24"));
        assert!(analysis.required_proof.description.contains("off=67"));
        assert!(analysis.required_proof.description.contains("size=1"));
        assert!(analysis
            .required_proof
            .description
            .contains("map_value(value_size=24"));
        assert!(analysis
            .required_proof
            .rejection_detail
            .contains("reaches byte 68"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost
                && event
                    .detail
                    .contains("map_value(value_size=24,range(smin=0,smax=63,umax=63)")
        }));
    }

    #[test]
    fn packet_bounds_case_instantiates_required_range() {
        let log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(26),
            "invalid access to packet, off=34 size=64, R3(id=0,off=34,r=42)",
            ProofObligation::PacketBounds,
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::PacketBounds
        );
        assert!(analysis.required_proof.description.contains("R3"));
        assert!(analysis.required_proof.description.contains("98"));
        assert!(analysis.required_proof.description.contains("42"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofEstablished
                && event.evidence == ProofEventEvidence::SourceComment
                && event.source.as_ref().unwrap().line == 52
        }));
    }

    #[test]
    fn nullable_pointer_case_points_at_unchecked_helper_result() {
        let log =
            include_str!("../../../bpfix-bench/cases/github-iovisor-bcc-10/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(7),
            "R0 invalid mem access 'map_value_or_null'",
            ProofObligation::NullablePointer,
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::NullablePointer
        );
        assert!(analysis.required_proof.description.contains("R0"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 24
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 25
        }));
    }

    #[test]
    fn environment_case_instantiates_helper_contract() {
        let log =
            include_str!("../../../bpfix-bench/cases/github-aya-rs-aya-1233/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(8),
            "program of this type cannot use helper bpf_probe_read#4",
            ProofObligation::EnvironmentCapability,
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::EnvironmentCapability
        );
        assert!(analysis
            .required_proof
            .description
            .contains("bpf_probe_read#4"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 13
        }));
    }

    #[test]
    fn stack_readability_case_instantiates_register_requirement() {
        let analysis = analyze_verifier_log(
            "0: (95) exit\nR0 !read_ok\n",
            Some(0),
            "R0 !read_ok",
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::StackInitialized
        );
        assert!(analysis.required_proof.description.contains("R0"));
        assert!(analysis
            .required_proof
            .rejection_detail
            .contains("not readable"));
    }

    #[test]
    fn reference_lifecycle_case_reports_acquire_and_exit() {
        let log = "\
; ref = bpf_ringbuf_reserve(&rb, 8, 0); @ prog.c:10
5: (85) call bpf_ringbuf_reserve#131 ; R0_w=ringbuf_mem_or_null(id=2,ref_obj_id=2) refs=2
; return 0; @ prog.c:11
6: (95) exit
Unreleased reference id=2 alloc_insn=5
";
        let analysis = analyze_verifier_log(
            log,
            Some(6),
            "Unreleased reference id=2 alloc_insn=5",
            ProofObligation::ReferenceLifecycle,
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::ReferenceLifecycle
        );
        assert!(analysis
            .required_proof
            .description
            .contains("reference id 2"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofEstablished
                && event.source.as_ref().unwrap().line == 10
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 11
        }));
    }
}
