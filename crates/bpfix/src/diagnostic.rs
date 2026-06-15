use anyhow::Result;
use bpfanalysis::{
    verifier_states_with_branch_deltas_from_log, CallbackKind, RegState, VerifierInsn,
    VerifierInsnKind,
};

use crate::family::ProofObligation;
use crate::input::is_verifier_error_line;
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
    MapValueGuardExceedsValueSize,
    MapPointerArgumentScalarZero,
    DynptrStackStorageAccess,
    ContextAccessSourceArgumentMismatch,
    ExceptionThrowWithLiveReference,
    MapLookupKeyArgumentUnreadable,
    PacketGuardUndercoversAccess,
    PacketMaxOffsetPrecisionBoundary,
    MapValueRelationPrecisionBoundary,
}

impl ProofSignal {
    pub(crate) const fn failure_class(self) -> &'static str {
        if self.is_environment_signal() {
            "environment_or_configuration"
        } else if self.is_source_state_signal() {
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
                "map relocation or loader path is missing for a helper map argument"
            }
            Self::DynptrStackStorageAccess => {
                "dynptr stack storage is being used as ordinary memory"
            }
            Self::ContextAccessSourceArgumentMismatch => {
                "tracing context argument type does not match the verifier-visible function signature"
            }
            Self::ExceptionThrowWithLiveReference => {
                "exception callback can throw while a verifier-tracked reference is still live"
            }
            Self::MapLookupKeyArgumentUnreadable => {
                "map lookup key pointer argument is unreadable"
            }
            Self::MapValueGuardExceedsValueSize => {
                "map-value index guard exceeds the map value size"
            }
            Self::PacketGuardUndercoversAccess => {
                "packet bounds check is narrower than the later packet access"
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
        if self.is_source_state_signal() || self.is_environment_signal() {
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
            Self::MapValueGuardExceedsValueSize => {
                "source bounds the map-value index to a range larger than the verifier-visible value size allows"
            }
            Self::MapPointerArgumentScalarZero => {
                "helper expects a map pointer, but verifier state shows scalar zero in the map argument register at the helper call; this matches a missing map relocation or raw-instruction loader path"
            }
            Self::DynptrStackStorageAccess => {
                "verifier state shows this stack slot contains dynptr state, but the rejected instruction reads it as ordinary stack bytes"
            }
            Self::ContextAccessSourceArgumentMismatch => {
                "verifier reports the traced-function argument at this context slot as PTR rather than a directly supported struct pointer, while the rejected source is a BPF_PROG argument load from the raw tracing context"
            }
            Self::ExceptionThrowWithLiveReference => {
                "verifier state reaches bpf_throw inside a callback frame while verifier-tracked references are live"
            }
            Self::MapLookupKeyArgumentUnreadable => {
                "bpf_map_lookup_elem consumes R2 as the key pointer, but verifier state reports that this helper argument register is not readable"
            }
            Self::PacketGuardUndercoversAccess => {
                "source has a packet bounds check, but verifier state after that check proves only a shorter packet range than the rejected access needs"
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
            Self::MapValueGuardExceedsValueSize => {
                "Clamp the map-value index to the array length or remaining bytes inside the map value; the guard must account for field offset plus access width."
            }
            Self::MapPointerArgumentScalarZero => {
                "Load the ELF object through libbpf or another loader that applies map relocations; raw instructions must not replace a map symbol with scalar zero."
            }
            Self::DynptrStackStorageAccess => {
                "Do not copy, read, or pass a dynptr object as ordinary bytes; use dynptr helpers to read data out of the dynptr and keep the dynptr object in its dedicated stack slot."
            }
            Self::ContextAccessSourceArgumentMismatch => {
                "Use only fentry arguments whose BTF type is verifier-supported at this slot, or avoid reading this argument through BPF_PROG when the traced function exposes it as an unsupported pointer type."
            }
            Self::ExceptionThrowWithLiveReference => {
                "Release verifier-tracked references before any callback path can throw, or avoid bpf_throw while a reference acquired by the caller is still live."
            }
            Self::MapLookupKeyArgumentUnreadable => {
                "Pass bpf_map_lookup_elem a pointer to initialized key storage, such as &key for a local key variable, not an uninitialized key pointer."
            }
            Self::PacketGuardUndercoversAccess => {
                "Move the data_end check to the final pointer expression and include the access width, for example check pointer + size before dereferencing pointer."
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
            Self::MapValueGuardExceedsValueSize => 5,
            Self::PacketGuardUndercoversAccess => 40,
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

    const fn is_environment_signal(self) -> bool {
        matches!(self, Self::MapPointerArgumentScalarZero)
    }

    const fn is_source_state_signal(self) -> bool {
        matches!(
            self,
            Self::ContextAccessSourceArgumentMismatch
                | Self::DynptrStackStorageAccess
                | Self::ExceptionThrowWithLiveReference
                | Self::MapLookupKeyArgumentUnreadable
                | Self::MapValueGuardExceedsValueSize
                | Self::PacketGuardUndercoversAccess
        )
    }

    pub(crate) fn can_override_base_failure_class(self, base_failure_class: &str) -> bool {
        match self {
            Self::ExceptionThrowWithLiveReference => {
                base_failure_class == "environment_or_configuration"
            }
            Self::ContextAccessSourceArgumentMismatch => {
                base_failure_class == "source_bug"
                    || base_failure_class == "environment_or_configuration"
            }
            _ => base_failure_class == "source_bug",
        }
    }

    pub(crate) const fn replaces_classifier_help(self) -> bool {
        matches!(
            self,
            Self::MapPointerArgumentScalarZero
                | Self::DynptrStackStorageAccess
                | Self::ContextAccessSourceArgumentMismatch
                | Self::ExceptionThrowWithLiveReference
                | Self::MapLookupKeyArgumentUnreadable
        )
    }

    pub(crate) const fn required_proof_override(self) -> Option<&'static str> {
        match self {
            Self::MapPointerArgumentScalarZero => Some(
                "apply the map relocation so bpf_map_lookup_elem receives a verifier-tracked map pointer instead of scalar zero",
            ),
            Self::DynptrStackStorageAccess => Some(
                "keep the dynptr object in its verifier-tracked stack slot and use dynptr helpers instead of reading or copying the dynptr storage as ordinary bytes",
            ),
            Self::ExceptionThrowWithLiveReference => Some(
                "release verifier-tracked references on every callback and exceptional path before bpf_throw can run",
            ),
            Self::MapLookupKeyArgumentUnreadable => Some(
                "pass a pointer to initialized map key storage in bpf_map_lookup_elem's second argument",
            ),
            Self::MapValueGuardExceedsValueSize => Some(
                "prove the map-value index plus field offset and access width stays below the map value size",
            ),
            _ => None,
        }
    }

    pub(crate) const fn primary_label_override(self) -> Option<&'static str> {
        match self {
            Self::MapPointerArgumentScalarZero => Some(
                "map helper argument is scalar zero because the map relocation was not applied",
            ),
            Self::DynptrStackStorageAccess => {
                Some("dynptr stack storage is read as ordinary memory")
            }
            Self::ExceptionThrowWithLiveReference => {
                Some("bpf_throw can run while verifier-tracked references are live")
            }
            Self::MapLookupKeyArgumentUnreadable => {
                Some("map lookup key argument register is unreadable at the helper call")
            }
            Self::MapValueGuardExceedsValueSize => {
                Some("map value index guard is wider than the value field can hold")
            }
            _ => None,
        }
    }

    pub(crate) const fn error_id_override(self) -> Option<&'static str> {
        match self {
            Self::MapPointerArgumentScalarZero => Some("BPFIX-E021"),
            Self::DynptrStackStorageAccess => Some("BPFIX-E012"),
            Self::ExceptionThrowWithLiveReference => Some("BPFIX-E004"),
            _ => None,
        }
    }
}

pub fn analyze_verifier_log(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    terminal_error: &str,
    terminal_call_target: Option<&str>,
    obligation: ProofObligation,
) -> Result<VerifierLogAnalysis> {
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
        ProofObligation::PacketBounds => events.extend(packet_bounds_events(
            log,
            &states,
            &branch_states,
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

fn packet_bounds_events(
    log: &str,
    states: &[VerifierInsn],
    branch_states: &[VerifierInsn],
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
        latest_sufficient_packet_range(states, terminal_pc, terminal_error, register).or_else(
            || {
                latest_sufficient_packet_guard_range(
                    log,
                    states,
                    branch_states,
                    source_events,
                    terminal_pc,
                    terminal_error,
                    rejected_source,
                    register,
                )
            },
        )
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
    } else if let Some((pc, range, required)) =
        latest_insufficient_packet_range(states, terminal_pc, terminal_error, register)
    {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            evidence: ProofEventEvidence::VerifierState,
            obligation: ProofObligation::PacketBounds,
            pc: Some(pc),
            source: source_for_pc_in_rejected_file(source_events, pc, rejected_source),
            register,
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

fn latest_reg_state_index_before(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<(usize, &VerifierInsn, &RegState)> {
    states
        .iter()
        .enumerate()
        .filter(|(_, state)| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .find_map(|(idx, state)| {
            state
                .regs
                .get(&reg)
                .map(|reg_state| (idx, state, reg_state))
        })
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
    log: &str,
    states: &[VerifierInsn],
    branch_states: &[VerifierInsn],
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
    terminal_error: &str,
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Option<(usize, u32, u32)> {
    let reg = register?;
    let required = packet_required_range(terminal_error)?;
    let (current_idx, _, current) = latest_reg_state_index_before(states, terminal_pc, reg)?;
    if current.reg_type != "pkt" || current.packet_range.is_some_and(|range| range >= required) {
        return None;
    }
    let rejected = rejected_source?;
    source_events
        .iter()
        .filter(|event| event.source.path == rejected.path)
        .filter(|event| event.source.line < rejected.line)
        .filter(|event| looks_like_packet_bounds_check(&event.source.text))
        .filter_map(|event| {
            let guard_pc = event.pc?;
            if terminal_pc.is_some_and(|pc| guard_pc > pc) {
                return None;
            }
            let mixed_id_same_register_history =
                has_prior_noid_same_register_packet_range_for_guard(
                    states,
                    source_events,
                    current_idx,
                    reg,
                    required,
                    current,
                    &event.source,
                );
            Some((guard_pc, mixed_id_same_register_history))
        })
        .flat_map(|(guard_pc, mixed_id_same_register_history)| {
            guard_branch_packet_operand_registers(log, branch_states, guard_pc, 6)
                .into_iter()
                .map(move |operand| (guard_pc, mixed_id_same_register_history, operand))
        })
        .filter_map(
            |(guard_source_pc, mixed_id_same_register_history, (branch_pc, branch_reg))| {
                branch_states
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
                && has_bounded_variable_packet_offset(current)
                && verifier_range_bounds_match(guard, current))
            .then_some(range)
        }
    }
}

fn has_bounded_variable_packet_offset(state: &RegState) -> bool {
    state.range.smin.is_some()
        || state.range.smax.is_some()
        || state.range.umin.is_some()
        || state.range.umax.is_some()
        || state.range.smin32.is_some()
        || state.range.smax32.is_some()
        || state.range.umin32.is_some()
        || state.range.umax32.is_some()
}

fn verifier_range_bounds_match(left: &RegState, right: &RegState) -> bool {
    left.range.smin == right.range.smin
        && left.range.smax == right.range.smax
        && left.range.umin == right.range.umin
        && left.range.umax == right.range.umax
        && left.range.smin32 == right.range.smin32
        && left.range.smax32 == right.range.smax32
        && left.range.umin32 == right.range.umin32
        && left.range.umax32 == right.range.umax32
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
    terminal_line: Option<usize>,
    register: Option<u8>,
    states: &'a [VerifierInsn],
    branch_states: &'a [VerifierInsn],
    source_events: &'a [SourceEvent],
    events: &'a [ProofEvent],
}

#[derive(Clone, Copy)]
struct TerminalInstruction<'a> {
    pc: usize,
    line: usize,
    tail: &'a str,
}

fn proof_signals(context: ProofSignalContext<'_>) -> Vec<ProofSignal> {
    let mut signals = Vec::new();
    if stack_alignment_lowering_signal(&context) {
        signals.push(ProofSignal::WideStackAlignment);
    }
    if pointer_shift_lowering_signal(&context) {
        signals.push(ProofSignal::PointerShiftDropsProvenance);
    }
    if modified_context_pointer_lowering_signal(&context) {
        signals.push(ProofSignal::ModifiedContextPointer);
    }
    if shared_instruction_pointer_merge_signal(&context) {
        signals.push(ProofSignal::SharedInstructionPointerMerge);
    }
    if subprogram_context_argument_dropped_signal(&context) {
        signals.push(ProofSignal::SubprogramContextArgumentDropped);
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
    if exception_throw_with_live_reference(
        context.log,
        context.terminal_pc,
        context.terminal_line,
        context.states,
    ) {
        signals.push(ProofSignal::ExceptionThrowWithLiveReference);
    }
    if map_pointer_argument_scalar_zero(
        context.log,
        context.terminal_error,
        context.terminal_pc,
        context.terminal_line,
        context.register,
        context.states,
        context.source_events,
        context.events,
    ) {
        signals.push(ProofSignal::MapPointerArgumentScalarZero);
    }
    if map_lookup_key_argument_unreadable(
        context.log,
        context.terminal_error,
        context.terminal_pc,
        context.terminal_line,
        context.register,
        context.events,
    ) {
        signals.push(ProofSignal::MapLookupKeyArgumentUnreadable);
    }
    if dynptr_stack_storage_access(&context) {
        signals.push(ProofSignal::DynptrStackStorageAccess);
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
    if packet_guard_undercovers_access(&context) {
        signals.push(ProofSignal::PacketGuardUndercoversAccess);
    }
    if map_value_wide_access(
        context.log,
        context.terminal_error,
        context.terminal_pc,
        context.terminal_line,
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
    if map_value_guard_exceeds_value_size(&context) {
        signals.push(ProofSignal::MapValueGuardExceedsValueSize);
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

fn exception_throw_with_live_reference(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    states: &[VerifierInsn],
) -> bool {
    if terminal_call_target(log, terminal_pc, terminal_line) != Some("bpf_throw") {
        return false;
    }
    latest_verifier_state_before(states, terminal_pc, terminal_line).is_some_and(|state| {
        state.callback_kind == Some(CallbackKind::Sync) && state.refs.is_some_and(|refs| refs > 0)
    })
}

fn map_pointer_argument_scalar_zero(
    log: &str,
    terminal_error: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    register: Option<u8>,
    states: &[VerifierInsn],
    source_events: &[SourceEvent],
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
    if !terminal_instruction_contains(log, terminal_pc, terminal_line, "call bpf_map_lookup_elem#")
    {
        return false;
    }
    let Some(rejected) = rejected_source(events) else {
        return false;
    };
    if !rejected.text.contains("bpf_map_lookup_elem") {
        return false;
    }
    let Some(map_argument) = first_call_argument(&rejected.text, "bpf_map_lookup_elem") else {
        return false;
    };
    if !map_argument_has_relocation_proof(&map_argument, rejected, source_events) {
        return false;
    }
    let Some(state) = latest_reg_state_before(states, terminal_pc, reg) else {
        return false;
    };
    state.reg_type == "scalar" && state.exact_value == Some(0)
}

fn map_lookup_key_argument_unreadable(
    log: &str,
    terminal_error: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    register: Option<u8>,
    events: &[ProofEvent],
) -> bool {
    if !terminal_error.contains("!read_ok") || register != Some(2) {
        return false;
    }
    if !terminal_instruction_contains(log, terminal_pc, terminal_line, "call bpf_map_lookup_elem#")
    {
        return false;
    }
    let Some(rejected) = rejected_source(events) else {
        return false;
    };
    if rejected
        .text
        .match_indices("bpf_map_lookup_elem")
        .take(2)
        .count()
        != 1
    {
        return false;
    }
    call_argument(&rejected.text, "bpf_map_lookup_elem", 1)
        .as_deref()
        .is_some_and(is_bare_identifier_argument)
}

fn dynptr_stack_storage_access(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::StackInitialized {
        return false;
    }
    if !context.terminal_error.contains("invalid read from stack") {
        return false;
    }
    if rejected_source(context.events).is_some_and(|source| {
        source.text.contains("bpf_dynptr_slice")
            && context.terminal_error.contains("memory, len pair")
    }) {
        return false;
    }
    let Some(access) = stack_access_range(context.terminal_error) else {
        return false;
    };
    latest_dynptr_stack_overlap(context, access).unwrap_or(false)
}

fn latest_dynptr_stack_overlap(
    context: &ProofSignalContext<'_>,
    access: StackByteRange,
) -> Option<bool> {
    for state in context
        .states
        .iter()
        .filter(|state| context.terminal_pc.is_none_or(|pc| state.pc <= pc))
        .filter(|state| {
            context
                .terminal_line
                .is_none_or(|line| state.log_line < line)
        })
        .rev()
    {
        let mut saw_overlap = false;
        let mut start_in_dynptr = false;
        let mut start_in_non_dynptr = false;
        let mut contains_dynptr = false;
        for (offset, stack) in &state.stack {
            let is_dynptr = stack
                .value
                .as_ref()
                .is_some_and(|value| value.reg_type.starts_with("dynptr"));
            let Some(range) = stack_value_range(*offset, is_dynptr) else {
                continue;
            };
            if !range.overlaps(access) {
                continue;
            }
            saw_overlap = true;
            if range.contains(access.start) {
                if is_dynptr {
                    start_in_dynptr = true;
                } else {
                    start_in_non_dynptr = true;
                }
            }
            if is_dynptr && access.contains_range(range) {
                contains_dynptr = true;
            }
        }
        if contains_dynptr || start_in_dynptr {
            return Some(true);
        }
        if start_in_non_dynptr || saw_overlap {
            return Some(false);
        }
    }
    None
}

#[derive(Clone, Copy)]
struct StackByteRange {
    start: i16,
    end: i16,
}

impl StackByteRange {
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    fn contains(self, offset: i16) -> bool {
        self.start <= offset && offset < self.end
    }

    fn contains_range(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

fn stack_value_range(offset: i16, is_dynptr: bool) -> Option<StackByteRange> {
    let size = if is_dynptr { 16 } else { 8 };
    Some(StackByteRange {
        start: offset,
        end: offset.checked_add(size)?,
    })
}

fn stack_access_range(message: &str) -> Option<StackByteRange> {
    let offset = parse_signed_i16_after(message, "off ")?;
    let size = parse_signed_i16_after(message, "size ")?;
    let end = offset.checked_add(size)?;
    Some(StackByteRange { start: offset, end })
}

fn parse_signed_i16_after(message: &str, marker: &str) -> Option<i16> {
    let start = message.find(marker)? + marker.len();
    let rest = message[start..].trim_start();
    let bytes = rest.as_bytes();
    let mut end = 0usize;
    if matches!(bytes.first(), Some(b'-' | b'+')) {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || matches!(rest.as_bytes().get(..end), Some([b'-']) | Some([b'+'])) {
        return None;
    }
    rest[..end].parse::<i16>().ok()
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
    if !map_value_variable_max_offset(state).is_some_and(|max| max > u64::from(max_index)) {
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

fn terminal_instruction_access_width(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<u32> {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .and_then(|instruction| memory_access_width(instruction.tail))
}

fn terminal_instruction_memory_offset(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<i64> {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .and_then(|instruction| memory_access_offset(instruction.tail))
}

fn terminal_instruction_contains(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    needle: &str,
) -> bool {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .is_some_and(|instruction| instruction.tail.contains(needle))
}

fn terminal_instruction_site(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<TerminalInstruction<'_>> {
    let pc = terminal_pc?;
    let lines = log.lines().collect::<Vec<_>>();
    let end = terminal_line
        .map(|line| line.saturating_sub(1))
        .unwrap_or(lines.len())
        .min(lines.len());
    let start = terminal_line
        .map(|line| verifier_fragment_start_line(log, line))
        .unwrap_or(1)
        .saturating_sub(1)
        .min(end);
    lines[start..end]
        .iter()
        .enumerate()
        .filter_map(|(offset, line)| {
            let line_number = start + offset + 1;
            let (line_pc, tail) = instruction_pc_tail(line.trim())?;
            (line_pc == pc && looks_like_bpf_instruction_tail(tail)).then_some(
                TerminalInstruction {
                    pc: line_pc,
                    line: line_number,
                    tail,
                },
            )
        })
        .last()
}

fn looks_like_bpf_instruction_tail(tail: &str) -> bool {
    let tail = tail.trim_start();
    tail.as_bytes().get(0) == Some(&b'(')
        && tail
            .as_bytes()
            .get(1..3)
            .is_some_and(|bytes| bytes.iter().all(u8::is_ascii_hexdigit))
        && tail.as_bytes().get(3) == Some(&b')')
}

fn terminal_call_target(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<&str> {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .and_then(|instruction| call_target_from_instruction_tail(instruction.tail))
}

fn call_target_from_instruction_tail(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    let call = loop {
        let token = tokens.next()?;
        if token == "call" {
            break tokens.next()?;
        }
    };
    call.split_once('#')
        .map(|(target, _)| target)
        .or(Some(call))
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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

fn verifier_fragment_start_line(log: &str, before_line: usize) -> usize {
    let lines = log.lines().collect::<Vec<_>>();
    let end = before_line.saturating_sub(1).min(lines.len());
    lines[..end]
        .iter()
        .enumerate()
        .rev()
        .find_map(|(idx, line)| {
            is_verifier_fragment_boundary(line.trim()).then_some(idx.saturating_add(2))
        })
        .unwrap_or(1)
}

fn is_verifier_fragment_boundary(line: &str) -> bool {
    line.starts_with("func#")
        || line.contains("-- BEGIN PROG LOAD LOG --")
        || line.contains("-- END PROG LOAD LOG --")
        || line.starts_with("processed ")
        || line.starts_with("verification time ")
        || line.starts_with("stack depth ")
        || (instruction_pc_tail(line).is_none() && is_verifier_error_line(line))
}

fn misaligned_stack_access_size(message: &str) -> Option<u32> {
    message
        .contains("misaligned stack access")
        .then(|| parse_u32_after(message, "size ").or_else(|| parse_u32_after(message, "size=")))
        .flatten()
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

fn memory_access_offset(line_after_pc: &str) -> Option<i64> {
    let operand = memory_access_operand(line_after_pc)?;
    if let Some((_, offset)) = operand.rsplit_once('+') {
        return parse_signed_decimal(offset);
    }
    if let Some((_, offset)) = operand.rsplit_once('-') {
        return parse_signed_decimal(offset).map(|value| -value);
    }
    register_operands(operand).first().map(|_| 0)
}

fn memory_access_base_register(line_after_pc: &str) -> Option<u8> {
    register_operands(memory_access_operand(line_after_pc)?)
        .first()
        .copied()
}

fn memory_access_operand(line_after_pc: &str) -> Option<&str> {
    let (_, after_marker) = line_after_pc.split_once("*)(")?;
    Some(after_marker.split_once(')')?.0.trim())
}

fn parse_signed_decimal(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    text.parse().ok()
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

fn latest_reg_state_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<&'a RegState> {
    states
        .iter()
        .filter(|state| state.log_line >= fragment_start_line)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .rev()
        .filter_map(|state| state.regs.get(&reg))
        .next()
}

fn latest_verifier_state_before(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<&VerifierInsn> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .filter(|state| terminal_line.is_none_or(|line| state.log_line < line))
        .next_back()
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
    log.lines()
        .filter_map(|line| instruction_pc_tail(line.trim()))
        .filter(|(pc, _)| *pc >= guard_pc && *pc <= max_pc)
        .filter_map(|(pc, tail)| {
            let regs = conditional_branch_registers(tail);
            (!regs.is_empty()).then_some((pc, regs))
        })
        .collect()
}

fn instruction_pc_tail(line: &str) -> Option<(usize, &str)> {
    let digits_len = line
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits_len == 0 || line.as_bytes().get(digits_len) != Some(&b':') {
        return None;
    }
    Some((
        line[..digits_len].parse().ok()?,
        line[digits_len + 1..].trim(),
    ))
}

fn conditional_branch_registers(tail: &str) -> Vec<u8> {
    let Some(condition) = tail
        .split_once(" if ")
        .map(|(_, condition)| condition)
        .or_else(|| tail.strip_prefix("if "))
    else {
        return Vec::new();
    };
    let condition = condition.split(" goto ").next().unwrap_or(condition);
    register_operands(condition)
}

fn register_operands(text: &str) -> Vec<u8> {
    let mut regs = Vec::new();
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    while idx + 1 < bytes.len() {
        if bytes[idx] != b'r' || !bytes[idx + 1].is_ascii_digit() {
            idx += 1;
            continue;
        }
        let start = idx + 1;
        let mut end = start + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if let Ok(reg) = text[start..end].parse::<u8>() {
            regs.push(reg);
        }
        idx = end;
    }
    regs
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
            || !scalar_guard_upper_bound_for_identifier(&source.text, index)
                .is_some_and(|upper| upper > max_index)
        {
            return false;
        }
        let Some(guard_pc) = event.pc else {
            return false;
        };
        if !context
            .terminal_pc
            .is_some_and(|terminal_pc| guard_pc < terminal_pc)
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
        if !context
            .terminal_line
            .is_some_and(|terminal_line| guard_log_line < terminal_line)
        {
            return false;
        }
        scalar_guard_verifier_state_links_to_map_value(
            context.log,
            context.branch_states,
            guard_pc,
            guard_log_line,
            context.terminal_pc,
            context.terminal_line,
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
    log: &str,
    states: &[VerifierInsn],
    guard_pc: usize,
    guard_log_line: usize,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    map_reg: u8,
    current: &RegState,
) -> bool {
    let lines = log.lines().collect::<Vec<_>>();
    states
        .iter()
        .filter(|state| state.pc >= guard_pc && state.pc <= guard_pc.saturating_add(3))
        .filter(|state| state.log_line > guard_log_line)
        .filter(|state| terminal_line.is_none_or(|terminal_line| state.log_line < terminal_line))
        .any(|state| {
            let Some(line) = state.log_line.checked_sub(1).and_then(|idx| lines.get(idx)) else {
                return false;
            };
            let Some((pc, tail)) = instruction_pc_tail(line.trim()) else {
                return false;
            };
            if pc != state.pc {
                return false;
            }
            let regs = conditional_branch_registers(tail);
            regs.iter().any(|reg| {
                state.regs.get(reg).is_some_and(|guard| {
                    guard.reg_type == "scalar"
                        && verifier_range_bounds_match(guard, current)
                        && map_value_add_uses_scalar_between(
                            log,
                            guard_pc,
                            guard_log_line,
                            terminal_pc,
                            terminal_line,
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
    log.lines()
        .enumerate()
        .filter(|(idx, _)| *idx + 1 > guard_log_line)
        .filter(|(idx, _)| terminal_line.is_none_or(|terminal_line| *idx + 1 < terminal_line))
        .filter_map(|(_, line)| instruction_pc_tail(line.trim()))
        .any(|(pc, tail)| {
            pc > guard_pc
                && pc < terminal_pc
                && instruction_adds_register(tail, map_reg, scalar_reg)
        })
}

fn instruction_adds_register(tail: &str, destination: u8, source: u8) -> bool {
    let mut tokens = tail.split_whitespace();
    while let Some(token) = tokens.next() {
        if register_token(token) != Some(destination) {
            continue;
        }
        if tokens.next() != Some("+=") {
            continue;
        }
        if tokens.next().and_then(register_token) == Some(source) {
            return true;
        }
    }
    false
}

fn register_token(token: &str) -> Option<u8> {
    let token = token.trim_end_matches(|ch| matches!(ch, ',' | ';'));
    let digits = token.strip_prefix('r')?;
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
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
    let digits = text
        .trim()
        .trim_end_matches(|ch| matches!(ch, 'u' | 'U' | 'l' | 'L'));
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
    let suffixless_zero = normalized.trim_end_matches(|ch| matches!(ch, 'u' | 'l')) == "0";
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
    let max_variable_offset = map_value_variable_max_offset(state);
    let fixed_offset = state.offset.and_then(|offset| u64::try_from(offset).ok());
    let max_offset = match (fixed_offset, max_variable_offset) {
        (Some(fixed), Some(variable)) => fixed.checked_add(variable),
        (Some(fixed), None) => Some(fixed),
        (None, Some(variable)) => Some(variable),
        (None, None) => None,
    };
    max_offset.is_some_and(|offset| offset >= u64::from(value_size))
}

fn map_value_variable_max_offset(state: &RegState) -> Option<u64> {
    state
        .range
        .umax
        .or_else(|| state.range.smax.and_then(|value| u64::try_from(value).ok()))
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
            None,
            "R5 invalid mem access 'scalar'",
            None,
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
            None,
            "value -2147483648 makes pkt pointer be out of bounds",
            None,
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
            None,
            "invalid access to map value, value_size=24 off=67 size=1; R0 max value is outside of the allowed memory range",
            None,
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
            None,
            "invalid access to packet, off=34 size=64, R3(id=0,off=34,r=42)",
            None,
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
            None,
            "R0 invalid mem access 'map_value_or_null'",
            None,
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
            None,
            "program of this type cannot use helper bpf_probe_read#4",
            None,
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
            None,
            "R0 !read_ok",
            None,
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
            None,
            "Unreleased reference id=2 alloc_insn=5",
            None,
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
