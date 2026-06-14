use anyhow::Result;
use bpfanalysis::{verifier_states_from_log, RegState, VerifierInsn};

use crate::family::ProofObligation;
use crate::proof::{
    instantiate_required_proof, packet_required_range, scalar_range_summary, RequiredProof,
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
    PacketVariableOffsetPrecisionBoundary,
    MapValueRelationPrecisionBoundary,
}

impl ProofSignal {
    pub(crate) const fn failure_class(self) -> &'static str {
        if self.is_verifier_precision_boundary() {
            "verifier_false_positive"
        } else {
            "lowering_artifact"
        }
    }

    pub(crate) const fn summary(self) -> &'static str {
        if self.is_verifier_precision_boundary() {
            "verifier precision limit may hide an existing safety proof"
        } else {
            "verifier-visible compiler lowering hides the required proof"
        }
    }

    pub(crate) const fn help_safety(self) -> &'static str {
        if self.is_verifier_precision_boundary() {
            "triage_only"
        } else {
            "repair_hint"
        }
    }

    pub(crate) const fn evidence_kind(self) -> &'static str {
        if self.is_verifier_precision_boundary() {
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
            Self::PacketVariableOffsetPrecisionBoundary => {
                "source-level packet bounds check is present, but the verifier appears to lose precision for a variable packet offset"
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
            Self::PacketVariableOffsetPrecisionBoundary => {
                "Treat this as a verifier precision boundary: clamp the variable packet offset to a small explicit maximum, then rederive and recheck the packet pointer immediately before the load."
            }
            Self::MapValueRelationPrecisionBoundary => {
                "Make the remaining map-value capacity explicit in one bounded variable, clamp the helper length to that variable, and pass that same value to the helper."
            }
        }
    }

    pub(crate) const fn confidence(self) -> &'static str {
        "medium"
    }

    const fn is_verifier_precision_boundary(self) -> bool {
        matches!(
            self,
            Self::PacketVariableOffsetPrecisionBoundary | Self::MapValueRelationPrecisionBoundary
        )
    }
}

pub fn analyze_verifier_log(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_error: &str,
    obligation: ProofObligation,
) -> Result<VerifierLogAnalysis> {
    let states = verifier_states_from_log(log)?;
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
                "verifier still sees R{reg} as {}, so the required scalar bound is not available at the use",
                scalar_range_summary(state)
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
    if context
        .events
        .iter()
        .any(packet_proof_lost_after_bounds_check)
    {
        signals.push(ProofSignal::PacketPointerProofLostAfterBoundsCheck);
    }
    if let Some(signal) = verifier_precision_signal(context.obligation, context.events) {
        signals.push(signal);
    }
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

fn verifier_precision_signal(
    obligation: ProofObligation,
    events: &[ProofEvent],
) -> Option<ProofSignal> {
    match obligation {
        ProofObligation::PacketBounds
            if source_text_contains(events, looks_like_packet_bounds_check)
                && source_text_contains_any(
                    events,
                    &[
                        "pkt_ctx->pkt_offset",
                        "field_offset",
                        "sizeof(struct extension)",
                        "server_name_extension",
                    ],
                ) =>
        {
            Some(ProofSignal::PacketVariableOffsetPrecisionBoundary)
        }
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
            (reg_state.reg_type == "scalar" && scalar_range_is_unsafe(reg_state))
                .then_some((state.pc, reg_state))
        })
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
