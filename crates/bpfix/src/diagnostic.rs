use anyhow::Result;
use bpfanalysis::{
    verifier_states_with_branch_deltas_from_log, CallbackKind, RegState, StackState, VerifierInsn,
    VerifierInsnKind,
};

use crate::family::ProofObligation;
use crate::input::is_verifier_error_line;
use crate::proof::{
    instantiate_required_proof, packet_required_range, verifier_value_summary, RequiredProof,
};
use crate::source::{
    call_target_from_instruction_tail, collect_source_events, latest_source_before,
    looks_like_null_check, looks_like_nullable_return, looks_like_packet_bounds_check,
    looks_like_reference_acquire, looks_like_reference_release, looks_like_scalar_guard,
    looks_like_stack_initialization, parse_instruction_line, source_for_pc, terminal_source,
    SourceEvent, SourceLocation,
};
use std::collections::HashMap;

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
    PacketAccessWithoutBoundsProof,
    MapValueWideAccess,
    MapValueCheckedOffsetRelationLost,
    MapValueGuardExceedsValueSize,
    MapValueAccessOutOfBounds,
    MemoryObjectAccessOutOfBounds,
    ReturnRangeOutOfBounds,
    StackVariableOffsetOutOfBounds,
    ScalarRangeUnsafeAtUse,
    MapPointerArgumentScalarZero,
    BtfFuncInfoMissing,
    SubprogramReferenceMetadataMissing,
    DynptrStackStorageAccess,
    DynptrUninitializedArgument,
    DynptrReferencedSlotOverwrite,
    DynptrReadonlyPacketWrite,
    DynptrStackSlotWriteOverlap,
    DynptrHelperArgumentStateMismatch,
    DynptrReleaseUnacquiredReference,
    DynptrSliceVariableLength,
    IteratorStackStorageAccess,
    IteratorHelperArgumentStateMismatch,
    IrqFlagStateMismatch,
    IrqRestoreOrderMismatch,
    IrqRestoreHelperClassMismatch,
    IrqStateLiveAtExit,
    SleepableCallInNonSleepableContext,
    CallbackCallWhileLocked,
    NullablePointerUseWithoutProof,
    TrustedNullableArgument,
    KfuncArgumentTypeMismatch,
    VerifierTypeContractMismatch,
    ModernBpfObjectProtocolViolation,
    ContextAccessSourceArgumentMismatch,
    ContextFieldUnavailable,
    KernelObjectFieldAccessMismatch,
    ExceptionThrowWithLiveReference,
    ReferenceLiveAtExit,
    ExceptionCallbackProtocolViolation,
    MapLookupKeyArgumentUnreadable,
    UnreadableProgramEntryArgument,
    UnreadableHelperArgument,
    MapPointerRawAccessContract,
    PerfEventOutputPacketAccess,
    UnreadableReturnRegister,
    LegacySkbLoadUnreadableRegister,
    HelperStackReadExceedsInitializedRange,
    HelperStackWriteBeyondFrame,
    ScalarValueUsedAsPointer,
    StalePointerAfterInvalidatingHelper,
    ProhibitedPointerArithmetic,
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
            Self::BtfFuncInfoMissing => {
                "BTF function metadata required by a subprogram call is missing"
            }
            Self::SubprogramReferenceMetadataMissing => {
                "subprogram argument reference metadata is missing at the BPF-to-BPF call"
            }
            Self::DynptrStackStorageAccess => {
                "dynptr stack storage is being used as ordinary memory"
            }
            Self::DynptrUninitializedArgument => {
                "dynptr helper argument is not an initialized verifier-tracked dynptr slot"
            }
            Self::DynptrReferencedSlotOverwrite => {
                "stack write or helper output overwrites a referenced verifier-tracked dynptr"
            }
            Self::DynptrReadonlyPacketWrite => {
                "writable dynptr slice is requested for packet data in a read-only context"
            }
            Self::DynptrStackSlotWriteOverlap => {
                "helper output or ordinary write overlaps live dynptr stack storage"
            }
            Self::DynptrHelperArgumentStateMismatch => {
                "dynptr helper argument has the wrong stack-slot or backing-memory state"
            }
            Self::DynptrReleaseUnacquiredReference => {
                "dynptr release helper is called after the dynptr reference was already consumed"
            }
            Self::DynptrSliceVariableLength => {
                "dynptr slice length is not verifier-visible as a constant"
            }
            Self::IteratorStackStorageAccess => {
                "iterator state storage is being read as ordinary memory"
            }
            Self::IteratorHelperArgumentStateMismatch => {
                "iterator helper argument has the wrong verifier-tracked lifecycle state"
            }
            Self::IrqFlagStateMismatch => {
                "IRQ flag helper argument has the wrong verifier-tracked lifecycle state"
            }
            Self::IrqRestoreOrderMismatch => {
                "IRQ state is restored outside the verifier-approved acquisition order"
            }
            Self::IrqRestoreHelperClassMismatch => {
                "IRQ restore helper class does not match the verifier-tracked state"
            }
            Self::IrqStateLiveAtExit => {
                "program exits while verifier-tracked IRQ state is still live"
            }
            Self::SleepableCallInNonSleepableContext => {
                "sleepable helper or subprogram call reaches a non-sleepable verifier context"
            }
            Self::CallbackCallWhileLocked => {
                "callback-invoking operation runs while a spin lock is held"
            }
            Self::NullablePointerUseWithoutProof => {
                "nullable pointer is used before the verifier sees a non-null proof"
            }
            Self::TrustedNullableArgument => {
                "trusted helper argument is still verifier-visible as nullable"
            }
            Self::KfuncArgumentTypeMismatch => {
                "kfunc argument does not have the verifier-required object or reference type"
            }
            Self::VerifierTypeContractMismatch => {
                "helper or kfunc argument has the wrong verifier-visible type"
            }
            Self::ModernBpfObjectProtocolViolation => {
                "modern BPF object helper or kfunc argument violates its verifier object protocol"
            }
            Self::ContextAccessSourceArgumentMismatch => {
                "tracing context argument type does not match the verifier-visible function signature"
            }
            Self::ContextFieldUnavailable => {
                "program context field is unavailable for the active verifier context"
            }
            Self::KernelObjectFieldAccessMismatch => {
                "kernel object field access targets a different struct than the verifier-visible pointer"
            }
            Self::ExceptionThrowWithLiveReference => {
                "exception callback can throw while a verifier-tracked reference is still live"
            }
            Self::ReferenceLiveAtExit => {
                "program exits while a verifier-tracked reference is still live"
            }
            Self::ExceptionCallbackProtocolViolation => {
                "subprogram or exception callback protocol contract is violated"
            }
            Self::MapLookupKeyArgumentUnreadable => {
                "map lookup key pointer argument is unreadable"
            }
            Self::UnreadableProgramEntryArgument => {
                "program entry argument register is unreadable in verifier state"
            }
            Self::UnreadableHelperArgument => {
                "helper argument register is unreadable at the call site"
            }
            Self::MapPointerRawAccessContract => {
                "map pointer is accessed as ordinary memory"
            }
            Self::PerfEventOutputPacketAccess => {
                "perf event output helper receives packet memory directly"
            }
            Self::UnreadableReturnRegister => {
                "return register is unreadable at BPF_EXIT"
            }
            Self::LegacySkbLoadUnreadableRegister => {
                "legacy skb load reads an implicit unreadable register"
            }
            Self::HelperStackReadExceedsInitializedRange => {
                "helper memory/length pair reads unwritten stack bytes"
            }
            Self::HelperStackWriteBeyondFrame => {
                "helper writable stack region crosses the verifier stack frame"
            }
            Self::ScalarValueUsedAsPointer => {
                "scalar or pkt_end value is used where the verifier requires a real pointer"
            }
            Self::StalePointerAfterInvalidatingHelper => {
                "skb/xdp or dynptr data pointer is reused after a helper invalidates it"
            }
            Self::ProhibitedPointerArithmetic => {
                "pointer arithmetic uses an operator the verifier cannot apply to pointer state"
            }
            Self::MapValueGuardExceedsValueSize => {
                "map-value index guard exceeds the map value size"
            }
            Self::MapValueAccessOutOfBounds => {
                "map-value access exceeds the verifier-visible value size"
            }
            Self::MemoryObjectAccessOutOfBounds => {
                "memory-object access exceeds the verifier-visible object size"
            }
            Self::ReturnRangeOutOfBounds => {
                "program return value is outside the verifier-required range"
            }
            Self::StackVariableOffsetOutOfBounds => {
                "stack variable-offset access crosses the verifier stack frame"
            }
            Self::ScalarRangeUnsafeAtUse => {
                "scalar range at the rejected use is still verifier-unsafe"
            }
            Self::PacketGuardUndercoversAccess => {
                "packet bounds check is narrower than the later packet access"
            }
            Self::PacketAccessWithoutBoundsProof => {
                "packet access reaches the use before the verifier has enough packet range"
            }
            signal if signal.is_verifier_precision_boundary() => {
                "verifier precision limit may hide an existing safety proof"
            }
            _ => "verifier-visible compiler lowering hides the required proof",
        }
    }

    pub(crate) const fn help_safety(self) -> &'static str {
        if matches!(
            self,
            Self::MapPointerArgumentScalarZero | Self::BtfFuncInfoMissing
        ) || self.is_verifier_precision_boundary()
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
            Self::MapValueAccessOutOfBounds => {
                "verifier state shows the rejected map-value pointer access crosses the declared value size"
            }
            Self::MemoryObjectAccessOutOfBounds => {
                "verifier state shows the rejected memory pointer has a fixed object size and the access crosses that object boundary"
            }
            Self::ReturnRangeOutOfBounds => {
                "verifier state reaches BPF_EXIT with a return register value or range outside the terminal return-value contract"
            }
            Self::StackVariableOffsetOutOfBounds => {
                "verifier state shows the stack pointer's variable byte interval can leave the valid BPF stack frame at the rejected access"
            }
            Self::ScalarRangeUnsafeAtUse => {
                "verifier state shows the rejected scalar or pointer-offset register still has an unsafe range at the use"
            }
            Self::MapPointerArgumentScalarZero => {
                "helper expects a map pointer, but verifier state shows scalar zero in the map argument register at the helper call; this matches a missing map relocation or raw-instruction loader path"
            }
            Self::BtfFuncInfoMissing => {
                "the verifier reports missing BTF func_info while the load log contains a multi-function BPF object or subprogram relocation"
            }
            Self::SubprogramReferenceMetadataMissing => {
                "the BPF-to-BPF call receives a source-level subprogram argument whose verifier reference type is UNKNOWN and has no size metadata"
            }
            Self::DynptrStackStorageAccess => {
                "verifier state shows this stack slot contains dynptr state, but the rejected instruction reads it as ordinary stack bytes"
            }
            Self::DynptrUninitializedArgument => {
                "verifier state shows the helper receives a stable stack pointer, but that stack slot is not the current initialized dynptr object"
            }
            Self::DynptrReferencedSlotOverwrite => {
                "verifier state shows the rejected write target overlaps a dynptr stack slot while a dynptr reference is still live"
            }
            Self::DynptrReadonlyPacketWrite => {
                "verifier state traces the dynptr argument back to packet-backed storage before the rejected bpf_dynptr_slice_rdwr call"
            }
            Self::DynptrStackSlotWriteOverlap => {
                "verifier state shows the rejected write target overlaps stack bytes that currently store live dynptr state"
            }
            Self::DynptrHelperArgumentStateMismatch => {
                "verifier state at the dynptr helper call shows an unstable dynptr slot, an interior dynptr pointer, or unsupported stack-backed input memory"
            }
            Self::DynptrReleaseUnacquiredReference => {
                "verifier state reaches a dynptr release helper with the exact dynptr stack slot but without a live reference"
            }
            Self::DynptrSliceVariableLength => {
                "the rejected dynptr slice helper uses R4 as its length argument, but verifier state shows R4 is still a scalar range rather than a known constant"
            }
            Self::IteratorStackStorageAccess => {
                "verifier state shows this stack slot contains iterator state, but the rejected instruction reads it as ordinary stack bytes"
            }
            Self::IteratorHelperArgumentStateMismatch => {
                "the rejected iterator helper receives an argument whose verifier state does not match the helper's required stack iterator lifecycle state"
            }
            Self::IrqFlagStateMismatch => {
                "the rejected IRQ helper receives a stack slot whose verifier state does not match the helper's save/restore lifecycle contract"
            }
            Self::IrqRestoreOrderMismatch => {
                "verifier state reaches an IRQ restore helper with a live IRQ flag slot while the verifier expects a newer outstanding IRQ state"
            }
            Self::IrqRestoreHelperClassMismatch => {
                "verifier state reaches an IRQ restore helper whose class does not match the newest live IRQ state origin"
            }
            Self::IrqStateLiveAtExit => {
                "verifier state reaches BPF_EXIT with live IRQ save references that have not been restored"
            }
            Self::SleepableCallInNonSleepableContext => {
                "verifier state reaches a sleepable helper or subprogram call while IRQ, RCU, preempt, or program-context rules require non-sleepable execution"
            }
            Self::CallbackCallWhileLocked => {
                "verifier branch state enters a synchronous callback from a call made after bpf_spin_lock and before the matching unlock"
            }
            Self::NullablePointerUseWithoutProof => {
                "verifier state shows the rejected pointer register is still a nullable helper result at the dereference, arithmetic, or helper-use site"
            }
            Self::TrustedNullableArgument => {
                "verifier state shows the rejected helper or kfunc argument is still a nullable RCU/trusted pointer at the call site"
            }
            Self::KfuncArgumentTypeMismatch => {
                "verifier state shows the rejected kfunc argument is a different pointer class than the kfunc contract requires"
            }
            Self::VerifierTypeContractMismatch => {
                "verifier state at the call site confirms the rejected argument register has the printed actual type, while the helper or kfunc contract requires a different verifier-visible type"
            }
            Self::ModernBpfObjectProtocolViolation => {
                "verifier state shows a modern BPF object protocol helper received a non-owned, non-RCU, non-referenced, or invalid cgroup, cpumask, kptr, or skb object argument"
            }
            Self::ContextAccessSourceArgumentMismatch => {
                "verifier reports the traced-function argument at this context slot as PTR rather than a directly supported struct pointer, while the rejected source is a BPF_PROG argument load from the raw tracing context"
            }
            Self::ContextFieldUnavailable => {
                "verifier state shows the rejected memory access uses a ctx register at an offset and width that the active program context does not expose"
            }
            Self::KernelObjectFieldAccessMismatch => {
                "verifier state shows the base register is a kernel object pointer for the reported struct, while CO-RE relocation metadata targets a different struct at the rejected offset"
            }
            Self::ExceptionThrowWithLiveReference => {
                "verifier state reaches bpf_throw inside a callback frame while verifier-tracked references are live"
            }
            Self::ReferenceLiveAtExit => {
                "verifier state reaches BPF_EXIT with the terminal reference id still live in the refs set"
            }
            Self::ExceptionCallbackProtocolViolation => {
                "verifier log validates a BPF subprogram or exception callback whose call path or return value violates the verifier protocol"
            }
            Self::MapLookupKeyArgumentUnreadable => {
                "bpf_map_lookup_elem consumes R2 as the key pointer, but verifier state reports that this helper argument register is not readable"
            }
            Self::UnreadableProgramEntryArgument => {
                "verifier entry state exposes only the program context and frame pointer, but the rejected instruction reads an entry argument register this program ABI did not provide"
            }
            Self::UnreadableHelperArgument => {
                "the rejected helper call consumes an argument register that has no verifier-readable state at the call site"
            }
            Self::MapPointerRawAccessContract => {
                "verifier state shows an ordinary memory access whose base register is a map_ptr, but map contents must be reached through a helper-returned map-value pointer"
            }
            Self::PerfEventOutputPacketAccess => {
                "verifier state at bpf_perf_event_output passes a packet pointer and scalar length as the data/size pair, but this helper cannot read packet memory directly"
            }
            Self::UnreadableReturnRegister => {
                "terminal verifier state rejects BPF_EXIT because the return register is not readable"
            }
            Self::LegacySkbLoadUnreadableRegister => {
                "verifier state for this legacy skb load has no readable state for the instruction's implicit skb register"
            }
            Self::HelperStackReadExceedsInitializedRange => {
                "verifier state shows the helper receives a stack pointer and length whose access range extends past the stack bytes proven written at that pointer"
            }
            Self::HelperStackWriteBeyondFrame => {
                "verifier state shows the helper receives a frame-pointer stack region whose byte range extends beyond the BPF stack frame"
            }
            Self::ScalarValueUsedAsPointer => {
                "verifier state at the rejected instruction shows the consumed register is scalar or pkt_end state, but the instruction uses it as a memory pointer or pointer-like value"
            }
            Self::StalePointerAfterInvalidatingHelper => {
                "verifier state shows this register previously held an skb/xdp or dynptr data pointer, but an intervening helper invalidated that pointer before the rejected memory access"
            }
            Self::ProhibitedPointerArithmetic => {
                "verifier state at the rejected instruction shows the target register is still pointer state, but the instruction applies a prohibited pointer arithmetic or bitwise operator"
            }
            Self::PacketGuardUndercoversAccess => {
                "source has a packet bounds check, but verifier state after that check proves only a shorter packet range than the rejected access needs"
            }
            Self::PacketAccessWithoutBoundsProof => {
                "verifier state shows the packet register's proven range is shorter than the rejected access requires at this instruction"
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
            Self::MapValueAccessOutOfBounds => {
                "Keep map-value field offsets, array indexes, and helper lengths inside the declared map value size; resize the map value or clamp the access before the load, store, or helper call."
            }
            Self::MemoryObjectAccessOutOfBounds => {
                "Keep dynptr slice or helper-returned memory accesses inside the verifier-reported object size; clamp the offset and width before dereferencing the memory pointer."
            }
            Self::ReturnRangeOutOfBounds => {
                "Return only values in the verifier-required range on every exit path; clamp or branch on the computed return value before BPF_EXIT."
            }
            Self::StackVariableOffsetOutOfBounds => {
                "Clamp the stack index so the final frame-pointer byte range stays within -512..0, accounting for the base offset and access width."
            }
            Self::MapPointerArgumentScalarZero => {
                "Load the ELF object through libbpf or another loader that applies map relocations; raw instructions must not replace a map symbol with scalar zero."
            }
            Self::BtfFuncInfoMissing => {
                "Rebuild and load the object with BTF func_info for BPF subprograms and callbacks; stripped or incomplete BTF metadata can make the verifier reject otherwise valid call shapes."
            }
            Self::SubprogramReferenceMetadataMissing => {
                "Use a verifier-supported BPF subprogram argument type instead of erasing the reference through an untyped pointer; keep the argument type metadata visible at the call boundary."
            }
            Self::DynptrStackStorageAccess => {
                "Do not copy, read, or pass a dynptr object as ordinary bytes; use dynptr helpers to read data out of the dynptr and keep the dynptr object in its dedicated stack slot."
            }
            Self::DynptrUninitializedArgument => {
                "Initialize the dynptr stack slot through a dynptr creation helper and pass that exact slot to later dynptr helpers; do not pass zeroed, clobbered, or unrelated stack bytes."
            }
            Self::DynptrReferencedSlotOverwrite => {
                "Do not overwrite or reinitialize a dynptr stack slot until the verifier-tracked dynptr reference has been submitted, discarded, or otherwise released."
            }
            Self::DynptrReadonlyPacketWrite => {
                "Use bpf_dynptr_slice for read-only packet dynptr access, or move writable packet access to a hook and helper combination where packet writes are verifier-allowed."
            }
            Self::DynptrStackSlotWriteOverlap => {
                "Keep helper output buffers and ordinary writes disjoint from stack bytes that store live dynptr state."
            }
            Self::DynptrHelperArgumentStateMismatch => {
                "Pass dynptr helpers the exact verifier-tracked stack slot and a supported backing memory object; avoid global dynptr storage, variable stack offsets, and interior dynptr pointers."
            }
            Self::DynptrReleaseUnacquiredReference => {
                "Release or submit each acquired dynptr exactly once; structure callback and error paths so a consumed dynptr cannot reach another release helper."
            }
            Self::DynptrSliceVariableLength => {
                "Use a constant dynptr slice length, or split runtime lengths into verifier-visible constant-size cases before calling the dynptr slice helper."
            }
            Self::IteratorStackStorageAccess => {
                "Treat iterator stack slots as opaque verifier state; use iterator helpers to read, advance, or destroy the iterator rather than loading the slot bytes directly."
            }
            Self::IteratorHelperArgumentStateMismatch => {
                "Keep iterator objects in verifier-tracked stack slots and call iterator create, next, and destroy helpers in the required lifecycle order."
            }
            Self::IrqFlagStateMismatch => {
                "Keep each IRQ flag stack slot dedicated to one save/restore pair, and pass restore the exact slot initialized by the matching save helper."
            }
            Self::IrqRestoreOrderMismatch => {
                "Restore IRQ save and lock state in strict reverse acquisition order, using the same flag slot returned by each save or lock helper."
            }
            Self::IrqRestoreHelperClassMismatch => {
                "Restore lock-acquired IRQ state with bpf_res_spin_unlock_irqrestore, and plain local IRQ state with bpf_local_irq_restore, in strict LIFO order."
            }
            Self::IrqStateLiveAtExit => {
                "Restore every verifier-tracked IRQ save state before returning or exiting, including states acquired inside BPF subprogram helpers."
            }
            Self::SleepableCallInNonSleepableContext => {
                "Move sleepable helper or global-subprogram calls outside IRQ/RCU/preempt-disabled regions, or use only non-sleepable operations from this program context."
            }
            Self::CallbackCallWhileLocked => {
                "Move callback-invoking operations such as rbtree insertion outside spin-locked regions, or release the lock before a callback path can call helpers, kfuncs, or bpf_throw."
            }
            Self::ScalarRangeUnsafeAtUse => {
                "Clamp or branch-check the exact scalar used by this helper, pointer arithmetic, stack access, or map-value access immediately before the rejected operation."
            }
            Self::NullablePointerUseWithoutProof => {
                "Check the helper result for null and keep the dereference, pointer arithmetic, or helper argument inside the same verifier-visible non-null branch."
            }
            Self::TrustedNullableArgument => {
                "Keep the RCU or trusted-pointer argument inside the verifier-visible non-null branch, or acquire a trusted reference before passing it to the helper or kfunc."
            }
            Self::KfuncArgumentTypeMismatch => {
                "Pass kfuncs the exact verifier-owned object type they require; do not cast stack memory, walked struct members, or plain kernel objects into BPF-owned kfunc object types."
            }
            Self::VerifierTypeContractMismatch => {
                "Pass the helper or kfunc the exact verifier-visible argument type it requires; use a real map pointer, stack pointer, packet pointer, ringbuf memory pointer, or trusted object pointer rather than casting or reusing a different pointer class."
            }
            Self::ModernBpfObjectProtocolViolation => {
                "Pass modern BPF object helpers and kfuncs only verifier-owned, RCU-protected, referenced, or valid kptr-storage objects as required by the specific helper contract."
            }
            Self::ContextAccessSourceArgumentMismatch => {
                "Use only fentry arguments whose BTF type is verifier-supported at this slot, or avoid reading this argument through BPF_PROG when the traced function exposes it as an unsupported pointer type."
            }
            Self::ContextFieldUnavailable => {
                "Use a program type or attach type that exposes this context field, read a verifier-supported context field, or derive the value from packet data instead of an unavailable context slot."
            }
            Self::KernelObjectFieldAccessMismatch => {
                "Read the field through a verifier-supported kernel-memory access path such as BPF_CORE_READ, instead of directly casting a verifier-visible kernel object pointer to a larger or different struct."
            }
            Self::ExceptionThrowWithLiveReference => {
                "Release verifier-tracked references before any callback path can throw, or avoid bpf_throw while a reference acquired by the caller is still live."
            }
            Self::ReferenceLiveAtExit => {
                "Release every verifier-tracked reference on all return paths; route success and error exits through cleanup blocks that release the exact live reference id before BPF_EXIT."
            }
            Self::ExceptionCallbackProtocolViolation => {
                "Keep exception callbacks out of ordinary subprogram call graphs, and make subprogram or callback returns satisfy the verifier's printed return-value contract."
            }
            Self::MapLookupKeyArgumentUnreadable => {
                "Pass bpf_map_lookup_elem a pointer to initialized key storage, such as &key for a local key variable, not an uninitialized key pointer."
            }
            Self::UnreadableProgramEntryArgument => {
                "Use the verifier-supported program ABI: read kprobe/syscall arguments from ctx or pt_regs helpers, or use a supported BPF_PROG-style wrapper."
            }
            Self::UnreadableHelperArgument => {
                "Set the helper argument register to a verifier-readable value immediately before the helper call, or remove the helper path that reaches the call without that argument."
            }
            Self::MapPointerRawAccessContract => {
                "Look up an element and read or write the returned map-value pointer; do not dereference or store through the map object pointer itself."
            }
            Self::PerfEventOutputPacketAccess => {
                "Copy packet bytes into stack or map storage first, or use a helper path that supports packet data instead of passing the packet pointer directly as the perf-event payload."
            }
            Self::UnreadableReturnRegister => {
                "Initialize R0 with a valid return code on every path before returning from the BPF program."
            }
            Self::LegacySkbLoadUnreadableRegister => {
                "Use verifier-recognized pointer or context access patterns instead of classic skb[] inline-assembly loads; do not rely on implicit registers outside the program ABI."
            }
            Self::HelperStackReadExceedsInitializedRange => {
                "Write every byte in the helper access range before the call, or reduce the length passed with the stack pointer."
            }
            Self::HelperStackWriteBeyondFrame => {
                "Move large scratch buffers to a per-CPU map, shrink the stack object, or pass a smaller helper length so the writable region stays inside the 512-byte BPF stack frame."
            }
            Self::ScalarValueUsedAsPointer => {
                "Use a verifier-recognized pointer at the access site; keep end sentinels, scalar offsets, and pointer bases separate, and reload or rederive the pointer from a supported context/helper before dereferencing it."
            }
            Self::StalePointerAfterInvalidatingHelper => {
                "After helpers that move or rewrite skb/xdp data, write dynptr backing storage, or replace dynptr backing state, discard old data and slice pointers and reacquire a fresh verifier-recognized pointer before dereferencing."
            }
            Self::ProhibitedPointerArithmetic => {
                "Avoid bitwise or unsupported arithmetic on pointer registers; preserve pointer provenance by keeping the pointer unchanged and applying scalar arithmetic to a separate offset before deriving a verifier-recognized pointer."
            }
            Self::PacketGuardUndercoversAccess => {
                "Move the data_end check to the final pointer expression and include the access width, for example check pointer + size before dereferencing pointer."
            }
            Self::PacketAccessWithoutBoundsProof => {
                "Move or add a data_end bounds check for the exact packet pointer and access width immediately before the load, store, or helper call that consumes it."
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
            Self::MapValueRelationPrecisionBoundary => 4,
            Self::MapValueGuardExceedsValueSize => 5,
            Self::MapValueAccessOutOfBounds => 6,
            Self::SleepableCallInNonSleepableContext => 7,
            Self::ModernBpfObjectProtocolViolation => 8,
            Self::VerifierTypeContractMismatch => 12,
            Self::PacketGuardUndercoversAccess => 40,
            Self::PacketAccessWithoutBoundsProof => 50,
            Self::ReturnRangeOutOfBounds => 55,
            Self::MemoryObjectAccessOutOfBounds => 55,
            Self::StackVariableOffsetOutOfBounds => 55,
            Self::ScalarRangeUnsafeAtUse => 60,
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
        matches!(
            self,
            Self::MapPointerArgumentScalarZero
                | Self::BtfFuncInfoMissing
                | Self::ContextFieldUnavailable
        )
    }

    const fn is_source_state_signal(self) -> bool {
        matches!(
            self,
            Self::ContextAccessSourceArgumentMismatch
                | Self::KernelObjectFieldAccessMismatch
                | Self::DynptrHelperArgumentStateMismatch
                | Self::DynptrReleaseUnacquiredReference
                | Self::DynptrStackStorageAccess
                | Self::DynptrUninitializedArgument
                | Self::DynptrReferencedSlotOverwrite
                | Self::DynptrReadonlyPacketWrite
                | Self::DynptrStackSlotWriteOverlap
                | Self::DynptrSliceVariableLength
                | Self::ExceptionCallbackProtocolViolation
                | Self::ExceptionThrowWithLiveReference
                | Self::ReferenceLiveAtExit
                | Self::CallbackCallWhileLocked
                | Self::NullablePointerUseWithoutProof
                | Self::IrqFlagStateMismatch
                | Self::IrqRestoreOrderMismatch
                | Self::IrqRestoreHelperClassMismatch
                | Self::IrqStateLiveAtExit
                | Self::SleepableCallInNonSleepableContext
                | Self::IteratorHelperArgumentStateMismatch
                | Self::IteratorStackStorageAccess
                | Self::KfuncArgumentTypeMismatch
                | Self::VerifierTypeContractMismatch
                | Self::ModernBpfObjectProtocolViolation
                | Self::MapLookupKeyArgumentUnreadable
                | Self::UnreadableProgramEntryArgument
                | Self::UnreadableHelperArgument
                | Self::MapPointerRawAccessContract
                | Self::PerfEventOutputPacketAccess
                | Self::UnreadableReturnRegister
                | Self::LegacySkbLoadUnreadableRegister
                | Self::HelperStackReadExceedsInitializedRange
                | Self::HelperStackWriteBeyondFrame
                | Self::ScalarValueUsedAsPointer
                | Self::StalePointerAfterInvalidatingHelper
                | Self::ProhibitedPointerArithmetic
                | Self::MapValueGuardExceedsValueSize
                | Self::MapValueAccessOutOfBounds
                | Self::MemoryObjectAccessOutOfBounds
                | Self::ReturnRangeOutOfBounds
                | Self::StackVariableOffsetOutOfBounds
                | Self::ScalarRangeUnsafeAtUse
                | Self::PacketAccessWithoutBoundsProof
                | Self::PacketGuardUndercoversAccess
                | Self::SubprogramReferenceMetadataMissing
                | Self::TrustedNullableArgument
        )
    }

    pub(crate) fn can_override_base_failure_class(self, base_failure_class: &str) -> bool {
        if base_failure_class == "unsupported_verifier_message" {
            return self.can_replace_unsupported_terminal();
        }
        match self {
            Self::ExceptionThrowWithLiveReference => {
                base_failure_class == "environment_or_configuration"
            }
            Self::ContextAccessSourceArgumentMismatch => {
                base_failure_class == "source_bug"
                    || base_failure_class == "environment_or_configuration"
            }
            Self::ContextFieldUnavailable => base_failure_class == "environment_or_configuration",
            Self::BtfFuncInfoMissing => {
                base_failure_class == "environment_or_configuration"
                    || base_failure_class == "unsupported_verifier_message"
            }
            Self::SubprogramReferenceMetadataMissing => {
                base_failure_class == "source_bug"
                    || base_failure_class == "environment_or_configuration"
                    || base_failure_class == "unsupported_verifier_message"
            }
            _ => base_failure_class == "source_bug",
        }
    }

    pub(crate) const fn can_replace_unsupported_terminal(self) -> bool {
        matches!(
            self,
            Self::ContextAccessSourceArgumentMismatch
                | Self::DynptrHelperArgumentStateMismatch
                | Self::DynptrReleaseUnacquiredReference
                | Self::DynptrStackStorageAccess
                | Self::DynptrStackSlotWriteOverlap
                | Self::DynptrSliceVariableLength
                | Self::ExceptionThrowWithLiveReference
                | Self::ReferenceLiveAtExit
                | Self::IrqFlagStateMismatch
                | Self::IrqRestoreOrderMismatch
                | Self::IrqRestoreHelperClassMismatch
                | Self::IrqStateLiveAtExit
                | Self::SleepableCallInNonSleepableContext
                | Self::IteratorHelperArgumentStateMismatch
                | Self::IteratorStackStorageAccess
                | Self::CallbackCallWhileLocked
                | Self::BtfFuncInfoMissing
                | Self::MapLookupKeyArgumentUnreadable
                | Self::MapPointerArgumentScalarZero
                | Self::MapValueGuardExceedsValueSize
                | Self::MapValueRelationPrecisionBoundary
                | Self::PacketGuardUndercoversAccess
                | Self::PacketMaxOffsetPrecisionBoundary
                | Self::SubprogramReferenceMetadataMissing
                | Self::TrustedNullableArgument
        )
    }

    pub(crate) const fn replaces_classifier_help(self) -> bool {
        matches!(
            self,
            Self::MapPointerArgumentScalarZero
                | Self::BtfFuncInfoMissing
                | Self::SubprogramReferenceMetadataMissing
                | Self::DynptrHelperArgumentStateMismatch
                | Self::DynptrReleaseUnacquiredReference
                | Self::DynptrStackStorageAccess
                | Self::DynptrUninitializedArgument
                | Self::DynptrReferencedSlotOverwrite
                | Self::DynptrReadonlyPacketWrite
                | Self::DynptrStackSlotWriteOverlap
                | Self::DynptrSliceVariableLength
                | Self::ReferenceLiveAtExit
                | Self::ExceptionCallbackProtocolViolation
                | Self::IrqFlagStateMismatch
                | Self::IrqRestoreOrderMismatch
                | Self::IrqRestoreHelperClassMismatch
                | Self::IrqStateLiveAtExit
                | Self::SleepableCallInNonSleepableContext
                | Self::CallbackCallWhileLocked
                | Self::IteratorHelperArgumentStateMismatch
                | Self::IteratorStackStorageAccess
                | Self::KfuncArgumentTypeMismatch
                | Self::VerifierTypeContractMismatch
                | Self::ModernBpfObjectProtocolViolation
                | Self::NullablePointerUseWithoutProof
                | Self::PacketAccessWithoutBoundsProof
                | Self::ScalarRangeUnsafeAtUse
                | Self::MemoryObjectAccessOutOfBounds
                | Self::ReturnRangeOutOfBounds
                | Self::StackVariableOffsetOutOfBounds
                | Self::MapValueAccessOutOfBounds
                | Self::TrustedNullableArgument
                | Self::ContextAccessSourceArgumentMismatch
                | Self::ContextFieldUnavailable
                | Self::KernelObjectFieldAccessMismatch
                | Self::ExceptionThrowWithLiveReference
                | Self::MapLookupKeyArgumentUnreadable
                | Self::UnreadableProgramEntryArgument
                | Self::UnreadableHelperArgument
                | Self::MapPointerRawAccessContract
                | Self::PerfEventOutputPacketAccess
                | Self::UnreadableReturnRegister
                | Self::LegacySkbLoadUnreadableRegister
                | Self::HelperStackReadExceedsInitializedRange
                | Self::HelperStackWriteBeyondFrame
                | Self::ScalarValueUsedAsPointer
                | Self::StalePointerAfterInvalidatingHelper
                | Self::ProhibitedPointerArithmetic
        )
    }

    pub(crate) const fn required_proof_override(self) -> Option<&'static str> {
        match self {
            Self::MapPointerArgumentScalarZero => Some(
                "apply the map relocation so bpf_map_lookup_elem receives a verifier-tracked map pointer instead of scalar zero",
            ),
            Self::BtfFuncInfoMissing => Some(
                "provide BTF func_info metadata for every BPF subprogram or callback reached by the loaded program",
            ),
            Self::SubprogramReferenceMetadataMissing => Some(
                "preserve verifier-visible reference type metadata across the BPF-to-BPF subprogram argument boundary",
            ),
            Self::DynptrStackStorageAccess => Some(
                "keep the dynptr object in its verifier-tracked stack slot and use dynptr helpers instead of reading or copying the dynptr storage as ordinary bytes",
            ),
            Self::DynptrUninitializedArgument => Some(
                "pass the exact verifier-tracked initialized dynptr stack slot to this helper argument",
            ),
            Self::DynptrReferencedSlotOverwrite => Some(
                "do not overwrite or reinitialize this dynptr stack slot while its verifier-tracked reference is still live",
            ),
            Self::DynptrReadonlyPacketWrite => Some(
                "use read-only dynptr packet access unless the program context permits writable packet data",
            ),
            Self::DynptrStackSlotWriteOverlap => Some(
                "keep helper output buffers and ordinary writes disjoint from live verifier-tracked dynptr stack slots",
            ),
            Self::DynptrHelperArgumentStateMismatch => Some(
                "pass dynptr helpers an exact verifier-tracked dynptr stack slot and supported non-stack backing memory",
            ),
            Self::DynptrReleaseUnacquiredReference => Some(
                "release or submit each verifier-tracked dynptr reference exactly once while the reference is still live",
            ),
            Self::DynptrSliceVariableLength => Some(
                "pass a verifier-known constant length to the dynptr slice helper",
            ),
            Self::IteratorStackStorageAccess => Some(
                "treat the iterator stack slot as opaque verifier state and access it only through iterator helpers",
            ),
            Self::IteratorHelperArgumentStateMismatch => Some(
                "pass bpf_iter_* helpers a verifier-tracked stack iterator slot in the lifecycle state required by the called helper",
            ),
            Self::IrqFlagStateMismatch => Some(
                "pass bpf_local_irq_save an empty stack flag slot and pass bpf_local_irq_restore the same verifier-tracked flag slot produced by save",
            ),
            Self::IrqRestoreOrderMismatch => Some(
                "restore each verifier-tracked IRQ state in strict LIFO order with the flag slot produced by its matching save or lock helper",
            ),
            Self::IrqRestoreHelperClassMismatch => Some(
                "restore each verifier-tracked IRQ state with the helper class that matches the save or lock helper that created it",
            ),
            Self::IrqStateLiveAtExit => Some(
                "restore every verifier-tracked IRQ save state before any BPF_EXIT can leave the program",
            ),
            Self::SleepableCallInNonSleepableContext => Some(
                "prove the sleepable helper or subprogram call cannot run in a non-sleepable IRQ, RCU, preempt-disabled, or program-context region",
            ),
            Self::CallbackCallWhileLocked => Some(
                "avoid entering verifier callback frames from operations executed while a spin lock is held",
            ),
            Self::NullablePointerUseWithoutProof => Some(
                "prove the nullable helper result is non-null in the same verifier-visible branch as this use",
            ),
            Self::TrustedNullableArgument => Some(
                "prove the RCU/trusted pointer argument is non-null and trusted at the helper or kfunc call site",
            ),
            Self::KfuncArgumentTypeMismatch => Some(
                "pass the kfunc a verifier-tracked object or reference whose BTF and ownership class exactly matches the kfunc argument contract",
            ),
            Self::VerifierTypeContractMismatch => Some(
                "pass the helper or kfunc argument register the exact verifier-visible type required by its contract at this call site",
            ),
            Self::ModernBpfObjectProtocolViolation => Some(
                "pass the helper or kfunc a verifier-approved object: valid kptr storage, a referenced/trusted object, or an RCU-protected object in the required state",
            ),
            Self::ExceptionThrowWithLiveReference => Some(
                "release verifier-tracked references on every callback and exceptional path before bpf_throw can run",
            ),
            Self::ReferenceLiveAtExit => Some(
                "release every verifier-tracked reference before each BPF_EXIT path can leave the program",
            ),
            Self::ExceptionCallbackProtocolViolation => Some(
                "keep exception callbacks reachable only through the verifier exception machinery and make subprogram or callback returns satisfy the verifier's printed return-value contract",
            ),
            Self::MapLookupKeyArgumentUnreadable => Some(
                "pass a pointer to initialized map key storage in bpf_map_lookup_elem's second argument",
            ),
            Self::UnreadableProgramEntryArgument => Some(
                "use the program-type context ABI instead of reading an entry argument register the verifier did not provide",
            ),
            Self::UnreadableHelperArgument => Some(
                "set the rejected helper argument register to a verifier-readable value on every path before the helper call",
            ),
            Self::MapPointerRawAccessContract => Some(
                "derive a verifier-visible map-value pointer with the proper map helper before reading or writing map contents",
            ),
            Self::PerfEventOutputPacketAccess => Some(
                "pass bpf_perf_event_output helper-readable stack or map memory, not a live packet pointer, as its data payload",
            ),
            Self::UnreadableReturnRegister => {
                Some("initialize R0 to a verifier-readable return value before BPF_EXIT")
            }
            Self::LegacySkbLoadUnreadableRegister => Some(
                "use verifier-recognized pointer or context access instead of a legacy skb[] load with an implicit unreadable register",
            ),
            Self::HelperStackReadExceedsInitializedRange => Some(
                "prove every byte in the helper memory/length pair access range is written before the call",
            ),
            Self::HelperStackWriteBeyondFrame => Some(
                "keep the helper writable stack range fully inside the current BPF stack frame, whose valid byte offsets are -512..0",
            ),
            Self::ScalarValueUsedAsPointer => Some(
                "prove the value consumed by this memory access or pointer operation is a verifier-recognized pointer, not scalar or pkt_end state",
            ),
            Self::StalePointerAfterInvalidatingHelper => Some(
                "preserve pointer provenance by reacquiring and rechecking the skb/xdp or dynptr data pointer after the helper that invalidates existing data pointers",
            ),
            Self::ProhibitedPointerArithmetic => Some(
                "preserve pointer state by avoiding bitwise or verifier-prohibited arithmetic on the pointer register",
            ),
            Self::ContextFieldUnavailable => Some(
                "access only context offsets and field widths exposed by the active BPF program type and attach point",
            ),
            Self::KernelObjectFieldAccessMismatch => Some(
                "read the kernel field through a verifier-supported helper or CO-RE access path instead of directly loading a field outside the verifier-visible object type",
            ),
            Self::MapValueGuardExceedsValueSize => Some(
                "prove the map-value index plus field offset and access width stays below the map value size",
            ),
            Self::MapValueAccessOutOfBounds => Some(
                "prove the map-value field offset plus access width stays below the declared map value size at the rejected access",
            ),
            Self::MemoryObjectAccessOutOfBounds => Some(
                "prove the memory pointer offset plus access width stays inside the verifier-reported object size at the rejected access",
            ),
            Self::ReturnRangeOutOfBounds => Some(
                "prove the value in R0 is inside the verifier-required return range at every BPF_EXIT",
            ),
            Self::StackVariableOffsetOutOfBounds => Some(
                "prove the final stack byte interval stays inside the verifier stack frame at the rejected access",
            ),
            Self::PacketAccessWithoutBoundsProof => Some(
                "prove this packet register has range at least off + size at the rejected load, store, or helper call",
            ),
            _ => None,
        }
    }

    pub(crate) const fn primary_label_override(self) -> Option<&'static str> {
        match self {
            Self::MapPointerArgumentScalarZero => Some(
                "map helper argument is scalar zero because the map relocation was not applied",
            ),
            Self::BtfFuncInfoMissing => {
                Some("BTF func_info metadata is missing for a subprogram call")
            }
            Self::SubprogramReferenceMetadataMissing => {
                Some("subprogram argument reference metadata is missing at this call")
            }
            Self::DynptrStackStorageAccess => {
                Some("dynptr stack storage is read as ordinary memory")
            }
            Self::DynptrUninitializedArgument => {
                Some("this helper argument is not an initialized dynptr stack slot")
            }
            Self::DynptrReferencedSlotOverwrite => {
                Some("this write overwrites a dynptr stack slot with a live reference")
            }
            Self::DynptrReadonlyPacketWrite => {
                Some("this writable slice request targets a packet-backed dynptr")
            }
            Self::DynptrStackSlotWriteOverlap => {
                Some("write target overlaps a live dynptr stack slot")
            }
            Self::DynptrHelperArgumentStateMismatch => {
                Some("dynptr helper argument does not match the verifier dynptr contract")
            }
            Self::DynptrReleaseUnacquiredReference => {
                Some("dynptr release helper is called without a live dynptr reference")
            }
            Self::DynptrSliceVariableLength => {
                Some("dynptr slice length argument is not a known constant")
            }
            Self::IteratorStackStorageAccess => {
                Some("iterator state stack slot is read as ordinary memory")
            }
            Self::IteratorHelperArgumentStateMismatch => {
                Some("iterator helper argument has the wrong lifecycle state")
            }
            Self::IrqFlagStateMismatch => {
                Some("IRQ flag helper argument has the wrong lifecycle state")
            }
            Self::IrqRestoreOrderMismatch => {
                Some("IRQ restore uses a flag slot before newer IRQ state is restored")
            }
            Self::IrqRestoreHelperClassMismatch => {
                Some("IRQ restore helper class does not match live state origin")
            }
            Self::IrqStateLiveAtExit => {
                Some("BPF_EXIT is reached while IRQ save state is still live")
            }
            Self::SleepableCallInNonSleepableContext => {
                Some("sleepable call is reachable from a non-sleepable verifier context")
            }
            Self::CallbackCallWhileLocked => {
                Some("callback path can run a forbidden call while a spin lock is held")
            }
            Self::NullablePointerUseWithoutProof => {
                Some("nullable pointer reaches this use without a non-null proof")
            }
            Self::TrustedNullableArgument => {
                Some("trusted helper argument remains nullable at the call site")
            }
            Self::KfuncArgumentTypeMismatch => {
                Some("kfunc argument has the wrong verifier object type")
            }
            Self::VerifierTypeContractMismatch => {
                Some("helper or kfunc argument has the wrong verifier-visible type")
            }
            Self::ModernBpfObjectProtocolViolation => {
                Some("modern BPF object argument violates its verifier protocol")
            }
            Self::ExceptionThrowWithLiveReference => {
                Some("bpf_throw can run while verifier-tracked references are live")
            }
            Self::ReferenceLiveAtExit => {
                Some("this exit is reachable with a verifier-tracked reference still live")
            }
            Self::ExceptionCallbackProtocolViolation => {
                Some("subprogram or exception callback violates the verifier-approved protocol")
            }
            Self::MapLookupKeyArgumentUnreadable => {
                Some("map lookup key argument register is unreadable at the helper call")
            }
            Self::UnreadableProgramEntryArgument => {
                Some("this argument register is not readable in verifier state")
            }
            Self::UnreadableHelperArgument => {
                Some("this helper argument register is not readable at the call")
            }
            Self::MapPointerRawAccessContract => {
                Some("this memory access uses the map object pointer as ordinary memory")
            }
            Self::PerfEventOutputPacketAccess => {
                Some("this helper call passes packet memory as the output payload")
            }
            Self::UnreadableReturnRegister => Some("this exit has no readable value in R0"),
            Self::LegacySkbLoadUnreadableRegister => {
                Some("this legacy skb load uses an implicit unreadable register")
            }
            Self::HelperStackReadExceedsInitializedRange => {
                Some("this helper reads unwritten stack bytes")
            }
            Self::HelperStackWriteBeyondFrame => {
                Some("this helper write crosses the verifier stack frame boundary")
            }
            Self::ScalarValueUsedAsPointer => {
                Some("this access consumes scalar or pkt_end state where a pointer is required")
            }
            Self::StalePointerAfterInvalidatingHelper => {
                Some("this access reuses a pointer invalidated by an earlier helper call")
            }
            Self::ProhibitedPointerArithmetic => {
                Some("this instruction applies a prohibited operation to pointer state")
            }
            Self::ContextFieldUnavailable => {
                Some("context access uses an unavailable offset or field width")
            }
            Self::KernelObjectFieldAccessMismatch => {
                Some("this load reads a field outside the verifier-visible kernel object type")
            }
            Self::MapValueGuardExceedsValueSize => {
                Some("map value index guard is wider than the value field can hold")
            }
            Self::MapValueAccessOutOfBounds => {
                Some("this map-value access crosses the declared value size")
            }
            Self::MemoryObjectAccessOutOfBounds => {
                Some("this memory access crosses the verifier-reported object size")
            }
            Self::ReturnRangeOutOfBounds => {
                Some("this exit returns a value outside the verifier-required range")
            }
            Self::StackVariableOffsetOutOfBounds => {
                Some("this stack access can leave the verifier stack frame")
            }
            Self::PacketAccessWithoutBoundsProof => {
                Some("packet range proof is too short for this access")
            }
            _ => None,
        }
    }

    pub(crate) const fn error_id_override(self) -> Option<&'static str> {
        match self {
            Self::MapPointerArgumentScalarZero => Some("BPFIX-E021"),
            Self::BtfFuncInfoMissing => Some("BPFIX-E021"),
            Self::SubprogramReferenceMetadataMissing => Some("BPFIX-E021"),
            Self::DynptrStackStorageAccess => Some("BPFIX-E012"),
            Self::DynptrUninitializedArgument => Some("BPFIX-E012"),
            Self::DynptrReferencedSlotOverwrite => Some("BPFIX-E012"),
            Self::DynptrReadonlyPacketWrite => Some("BPFIX-E012"),
            Self::DynptrStackSlotWriteOverlap => Some("BPFIX-E019"),
            Self::DynptrHelperArgumentStateMismatch => Some("BPFIX-E019"),
            Self::DynptrReleaseUnacquiredReference => Some("BPFIX-E019"),
            Self::DynptrSliceVariableLength => Some("BPFIX-E019"),
            Self::IteratorStackStorageAccess => Some("BPFIX-E014"),
            Self::IteratorHelperArgumentStateMismatch => Some("BPFIX-E014"),
            Self::IrqFlagStateMismatch => Some("BPFIX-E020"),
            Self::IrqRestoreOrderMismatch => Some("BPFIX-E013"),
            Self::IrqRestoreHelperClassMismatch => Some("BPFIX-E013"),
            Self::IrqStateLiveAtExit => Some("BPFIX-E013"),
            Self::SleepableCallInNonSleepableContext => Some("BPFIX-E016"),
            Self::CallbackCallWhileLocked => Some("BPFIX-E015"),
            Self::NullablePointerUseWithoutProof => Some("BPFIX-E002"),
            Self::TrustedNullableArgument => Some("BPFIX-E015"),
            Self::KfuncArgumentTypeMismatch => Some("BPFIX-E013"),
            Self::VerifierTypeContractMismatch => Some("BPFIX-E008"),
            Self::ModernBpfObjectProtocolViolation => Some("BPFIX-E023"),
            Self::PacketAccessWithoutBoundsProof => Some("BPFIX-E001"),
            Self::ExceptionThrowWithLiveReference => Some("BPFIX-E004"),
            Self::ReferenceLiveAtExit => Some("BPFIX-E004"),
            Self::ExceptionCallbackProtocolViolation => Some("BPFIX-E013"),
            Self::UnreadableProgramEntryArgument => Some("BPFIX-E011"),
            Self::UnreadableHelperArgument => Some("BPFIX-E010"),
            Self::MapPointerRawAccessContract => Some("BPFIX-E010"),
            Self::PerfEventOutputPacketAccess => Some("BPFIX-E010"),
            Self::UnreadableReturnRegister => Some("BPFIX-E003"),
            Self::LegacySkbLoadUnreadableRegister => Some("BPFIX-E003"),
            Self::HelperStackReadExceedsInitializedRange => Some("BPFIX-E003"),
            Self::HelperStackWriteBeyondFrame => Some("BPFIX-E006"),
            Self::MapValueAccessOutOfBounds => Some("BPFIX-E005"),
            Self::MemoryObjectAccessOutOfBounds => Some("BPFIX-E005"),
            Self::ReturnRangeOutOfBounds => Some("BPFIX-E005"),
            Self::StackVariableOffsetOutOfBounds => Some("BPFIX-E005"),
            Self::ScalarValueUsedAsPointer => Some("BPFIX-E011"),
            Self::StalePointerAfterInvalidatingHelper => Some("BPFIX-E011"),
            Self::KernelObjectFieldAccessMismatch => Some("BPFIX-E011"),
            _ => None,
        }
    }
}

#[cfg(test)]
pub fn analyze_verifier_log(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    terminal_error: &str,
    terminal_call_target: Option<&str>,
    obligation: ProofObligation,
) -> Result<VerifierLogAnalysis> {
    analyze_verifier_log_with_context(
        log,
        log,
        terminal_pc,
        terminal_line,
        terminal_error,
        terminal_call_target,
        obligation,
    )
}

pub fn analyze_verifier_log_with_context(
    log: &str,
    full_log: &str,
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
        full_log,
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
    full_log: &'a str,
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

#[derive(Clone, Copy)]
struct TerminalInstruction<'a> {
    pc: usize,
    line: usize,
    tail: &'a str,
}

#[derive(Clone, Debug)]
struct PathVerifierSnapshot {
    frame: usize,
    regs: HashMap<u8, RegState>,
    stack: HashMap<i16, StackState>,
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
    if let Some(signal) = verifier_precision_signal(&context) {
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
    if context_field_unavailable(&context) {
        signals.push(ProofSignal::ContextFieldUnavailable);
    }
    if kernel_object_field_access_mismatch(&context) {
        signals.push(ProofSignal::KernelObjectFieldAccessMismatch);
    }
    if exception_throw_with_live_reference(
        context.log,
        context.terminal_pc,
        context.terminal_line,
        context.states,
    ) {
        signals.push(ProofSignal::ExceptionThrowWithLiveReference);
    }
    if reference_live_at_exit(&context) {
        signals.push(ProofSignal::ReferenceLiveAtExit);
    }
    if exception_callback_protocol_violation(&context) {
        signals.push(ProofSignal::ExceptionCallbackProtocolViolation);
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
    if btf_func_info_missing(&context) {
        signals.push(ProofSignal::BtfFuncInfoMissing);
    }
    if subprogram_reference_metadata_missing(&context) {
        signals.push(ProofSignal::SubprogramReferenceMetadataMissing);
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
    if unreadable_program_entry_argument(&context) {
        signals.push(ProofSignal::UnreadableProgramEntryArgument);
    }
    if unreadable_helper_argument(&context) {
        signals.push(ProofSignal::UnreadableHelperArgument);
    }
    if map_pointer_raw_access_contract(&context) {
        signals.push(ProofSignal::MapPointerRawAccessContract);
    }
    if perf_event_output_packet_access(&context) {
        signals.push(ProofSignal::PerfEventOutputPacketAccess);
    }
    if unreadable_return_register(&context) {
        signals.push(ProofSignal::UnreadableReturnRegister);
    }
    if legacy_skb_load_unreadable_register(&context) {
        signals.push(ProofSignal::LegacySkbLoadUnreadableRegister);
    }
    if helper_stack_read_exceeds_initialized_range(&context) {
        signals.push(ProofSignal::HelperStackReadExceedsInitializedRange);
    }
    if helper_stack_write_beyond_frame(&context) {
        signals.push(ProofSignal::HelperStackWriteBeyondFrame);
    }
    if dynptr_uninitialized_argument(&context) {
        signals.push(ProofSignal::DynptrUninitializedArgument);
    }
    if dynptr_referenced_slot_overwrite(&context) {
        signals.push(ProofSignal::DynptrReferencedSlotOverwrite);
    }
    if dynptr_readonly_packet_write(&context) {
        signals.push(ProofSignal::DynptrReadonlyPacketWrite);
    }
    if dynptr_stack_slot_write_overlap(&context) {
        signals.push(ProofSignal::DynptrStackSlotWriteOverlap);
    }
    if dynptr_stack_storage_access(&context) {
        signals.push(ProofSignal::DynptrStackStorageAccess);
    }
    if dynptr_helper_argument_state_mismatch(&context) {
        signals.push(ProofSignal::DynptrHelperArgumentStateMismatch);
    }
    if dynptr_release_unacquired_reference(&context) {
        signals.push(ProofSignal::DynptrReleaseUnacquiredReference);
    }
    if dynptr_slice_variable_length(&context) {
        signals.push(ProofSignal::DynptrSliceVariableLength);
    }
    if iterator_helper_argument_state_mismatch(&context) {
        signals.push(ProofSignal::IteratorHelperArgumentStateMismatch);
    }
    if iterator_stack_storage_access(&context) {
        signals.push(ProofSignal::IteratorStackStorageAccess);
    }
    if irq_flag_state_mismatch(&context) {
        signals.push(ProofSignal::IrqFlagStateMismatch);
    }
    if irq_restore_order_mismatch(&context) {
        signals.push(ProofSignal::IrqRestoreOrderMismatch);
    }
    if irq_restore_helper_class_mismatch(&context) {
        signals.push(ProofSignal::IrqRestoreHelperClassMismatch);
    }
    if irq_state_live_at_exit(&context) {
        signals.push(ProofSignal::IrqStateLiveAtExit);
    }
    if sleepable_call_in_non_sleepable_context(&context) {
        signals.push(ProofSignal::SleepableCallInNonSleepableContext);
    }
    if callback_call_while_locked(&context) {
        signals.push(ProofSignal::CallbackCallWhileLocked);
    }
    if nullable_pointer_use_without_proof(&context) {
        signals.push(ProofSignal::NullablePointerUseWithoutProof);
    }
    if modern_bpf_object_protocol_violation(&context) {
        signals.push(ProofSignal::ModernBpfObjectProtocolViolation);
    }
    if kfunc_argument_type_mismatch(&context) {
        signals.push(ProofSignal::KfuncArgumentTypeMismatch);
    }
    if trusted_nullable_argument(&context) {
        signals.push(ProofSignal::TrustedNullableArgument);
    }
    if verifier_type_contract_mismatch(&context) {
        signals.push(ProofSignal::VerifierTypeContractMismatch);
    }
    if memory_object_access_out_of_bounds(&context) {
        signals.push(ProofSignal::MemoryObjectAccessOutOfBounds);
    }
    if return_range_out_of_bounds(&context) {
        signals.push(ProofSignal::ReturnRangeOutOfBounds);
    }
    if stack_variable_offset_out_of_bounds(&context) {
        signals.push(ProofSignal::StackVariableOffsetOutOfBounds);
    }
    if scalar_range_unsafe_at_use(&context) {
        signals.push(ProofSignal::ScalarRangeUnsafeAtUse);
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
    if packet_access_without_bounds_proof(&context) {
        signals.push(ProofSignal::PacketAccessWithoutBoundsProof);
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
    if map_value_access_out_of_bounds(&context) {
        signals.push(ProofSignal::MapValueAccessOutOfBounds);
    }
    if signals.is_empty() && stale_pointer_after_invalidating_helper(&context) {
        signals.push(ProofSignal::StalePointerAfterInvalidatingHelper);
    }
    if signals.is_empty() && scalar_value_used_as_pointer(&context) {
        signals.push(ProofSignal::ScalarValueUsedAsPointer);
    }
    if signals.is_empty() && prohibited_pointer_arithmetic(&context) {
        signals.push(ProofSignal::ProhibitedPointerArithmetic);
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

fn context_field_unavailable(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid bpf_context access")
        || terminal.contains("invalid ctx access")
        || terminal.contains("invalid access to context"))
    {
        return false;
    }
    if terminal_error_has_nearby_prior_line(context.log, context.terminal_error, 3, |line| {
        line.contains("type PTR is not a struct")
    }) {
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
    if parse_u32_after(context.terminal_error, "size=")
        .is_some_and(|size| memory_access_width(instruction.tail) != Some(size))
    {
        return false;
    }
    if parse_u32_after(context.terminal_error, "off=")
        .map(i64::from)
        .is_some_and(|offset| memory_access_offset(instruction.tail) != Some(offset))
    {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    latest_reg_state_before_instruction(context.states, instruction, fragment_start, base_reg)
        .is_some_and(|state| state.reg_type == "ctx")
}

fn kernel_object_field_access_mismatch(context: &ProofSignalContext<'_>) -> bool {
    let Some(reported_struct) = access_beyond_struct_name(context.terminal_error) else {
        return false;
    };
    let Some(access_offset) = access_beyond_struct_offset(context.terminal_error) else {
        return false;
    };
    let Some(access_size) = access_beyond_struct_size(context.terminal_error) else {
        return false;
    };
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if memory_access_offset(instruction.tail) != Some(i64::from(access_offset)) {
        return false;
    }
    if memory_access_width(instruction.tail) != Some(access_size) {
        return false;
    }
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
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
    if !kernel_pointer_state_matches_struct(&base_state.reg_type, reported_struct) {
        return false;
    }
    let Some(before_line) = terminal_error_line_in_log(context.full_log, context.terminal_error)
    else {
        return false;
    };
    let Some((program_name, window_start)) =
        current_libbpf_program_scope(context.full_log, before_line)
    else {
        return false;
    };
    core_relocation_struct_for_instruction(
        context.full_log,
        window_start,
        before_line,
        program_name,
        instruction.pc,
        access_offset,
    )
    .is_some_and(|relocated_struct| !kernel_struct_names_match(relocated_struct, reported_struct))
}

fn current_libbpf_program_scope(log: &str, before_line: usize) -> Option<(&str, usize)> {
    let lines = log.lines().collect::<Vec<_>>();
    let before = before_line.saturating_sub(1).min(lines.len());
    let (begin_idx, program_name) =
        lines[..before]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(idx, line)| {
                line.contains("-- BEGIN PROG LOAD LOG --")
                    .then(|| libbpf_program_name(line).map(|name| (idx, name)))
                    .flatten()
            })?;
    let window_start = current_libbpf_load_window_start(&lines, begin_idx);
    Some((program_name, window_start))
}

fn current_libbpf_load_window_start(lines: &[&str], before_idx: usize) -> usize {
    let prior = &lines[..before_idx];
    if let Some(idx) = prior
        .iter()
        .enumerate()
        .rev()
        .find_map(|(idx, line)| line.starts_with("libbpf: loading object").then_some(idx))
    {
        return idx + 2;
    }
    prior
        .iter()
        .enumerate()
        .rev()
        .find_map(|(idx, line)| line.contains("-- END PROG LOAD LOG --").then_some(idx + 2))
        .unwrap_or(1)
}

fn libbpf_program_name(line: &str) -> Option<&str> {
    let (_, tail) = line.split_once("prog '")?;
    let (name, _) = tail.split_once("':")?;
    (!name.is_empty()).then_some(name)
}

fn line_is_libbpf_program(line: &str, program_name: &str) -> bool {
    libbpf_program_name(line).is_some_and(|name| name == program_name)
}

fn core_relocation_struct_for_instruction<'a>(
    log: &'a str,
    window_start: usize,
    before_line: usize,
    program_name: &str,
    pc: usize,
    offset: u32,
) -> Option<&'a str> {
    let patched_pc = u32::try_from(pc).ok()?;
    let lines = log.lines().collect::<Vec<_>>();
    let end = before_line.saturating_sub(1).min(lines.len());
    let start = window_start.saturating_sub(1).min(end);
    let scoped_lines = &lines[start..end];
    let patched_relo_ids = scoped_lines
        .iter()
        .filter_map(|line| {
            if !line_is_libbpf_program(line, program_name)
                || parse_u32_after(line, "patched insn #") != Some(patched_pc)
                || !core_patched_offset_matches(line, offset)
            {
                return None;
            }
            parse_u32_after(line, "relo #")
        })
        .collect::<Vec<_>>();
    scoped_lines
        .iter()
        .rev()
        .filter(|line| line_is_libbpf_program(line, program_name))
        .filter(|line| {
            parse_u32_after(line, "relo #")
                .is_some_and(|relo_id| patched_relo_ids.contains(&relo_id))
        })
        .find_map(|line| core_relocation_struct_name(line))
}

fn core_patched_offset_matches(line: &str, offset: u32) -> bool {
    parse_u32_after(line, " off ") == Some(offset) || parse_u32_after(line, " -> ") == Some(offset)
}

fn core_relocation_struct_name(line: &str) -> Option<&str> {
    let (_, tail) = line.split_once("struct ")?;
    let name = tail
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .next()?;
    (!name.is_empty()).then_some(name)
}

fn terminal_error_line_in_log(log: &str, terminal_error: &str) -> Option<usize> {
    let lines = log.lines().collect::<Vec<_>>();
    lines
        .iter()
        .enumerate()
        .rev()
        .find_map(|(idx, line)| line.contains(terminal_error).then_some(idx + 1))
}

fn access_beyond_struct_name(terminal_error: &str) -> Option<&str> {
    let (_, tail) = terminal_error.split_once("access beyond struct ")?;
    let name = tail
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .next()?;
    (!name.is_empty()).then_some(name)
}

fn access_beyond_struct_offset(terminal_error: &str) -> Option<u32> {
    parse_u32_after(terminal_error, "off ").or_else(|| parse_u32_after(terminal_error, "off="))
}

fn access_beyond_struct_size(terminal_error: &str) -> Option<u32> {
    parse_u32_after(terminal_error, "size ").or_else(|| parse_u32_after(terminal_error, "size="))
}

fn kernel_pointer_state_matches_struct(reg_type: &str, struct_name: &str) -> bool {
    let expected = format!("ptr_{}", normalized_kernel_struct_name(struct_name));
    reg_type == expected
}

fn kernel_struct_names_match(left: &str, right: &str) -> bool {
    normalized_kernel_struct_name(left) == normalized_kernel_struct_name(right)
}

fn normalized_kernel_struct_name(name: &str) -> &str {
    name.trim()
        .strip_prefix("struct ")
        .unwrap_or_else(|| name.trim())
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

fn reference_live_at_exit(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::ReferenceLifecycle | ProofObligation::Unknown
    ) {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("unreleased reference id=") {
        return false;
    }
    let Some(ref_id) = parse_u32_after(&terminal, "reference id=") else {
        return false;
    };
    let Some(alloc_pc) =
        parse_u32_after(&terminal, "alloc_insn=").and_then(|pc| usize::try_from(pc).ok())
    else {
        return false;
    };
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !instruction_is_bpf_exit(instruction.tail) {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some(exit_state) =
        latest_verifier_state_at_or_before_instruction(context.states, instruction, fragment_start)
    else {
        return false;
    };
    exit_state.ref_ids.contains(&ref_id)
        && reference_alloc_call_before_exit(
            context,
            fragment_start,
            instruction.line,
            alloc_pc,
            ref_id,
        )
}

fn reference_alloc_call_before_exit(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    before_line: usize,
    alloc_pc: usize,
    ref_id: u32,
) -> bool {
    let Some(alloc_instruction) =
        instruction_site_before_line(context.log, alloc_pc, fragment_start, before_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(alloc_instruction.tail) else {
        return false;
    };
    reference_acquire_target(target)
        && context
            .states
            .iter()
            .filter(|state| state.log_line >= alloc_instruction.line)
            .filter(|state| state.log_line < before_line)
            .any(|state| state.ref_ids.contains(&ref_id))
}

fn reference_acquire_target(target: &str) -> bool {
    target.contains("_acquire")
        || target.contains("_create")
        || target.ends_with("_new")
        || target.starts_with("bpf_ringbuf_reserve")
        || target == "bpf_kptr_xchg"
        || target == "bpf_obj_new"
}

fn instruction_is_bpf_exit(tail: &str) -> bool {
    let mut tokens = tail.split_whitespace();
    tokens.next() == Some("(95)") && tokens.next() == Some("exit")
}

fn exception_callback_protocol_violation(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if terminal.contains("cannot call exception cb directly") {
        return direct_exception_callback_call(context);
    }
    if terminal.contains("at program exit")
        && terminal.contains("register r0")
        && terminal.contains("should have been in")
    {
        return exception_callback_return_contract_mismatch(context);
    }
    false
}

fn direct_exception_callback_call(context: &ProofSignalContext<'_>) -> bool {
    let Some(terminal_line) = context.terminal_line else {
        return false;
    };
    let Some(reported_pc) =
        parse_u32_after(context.terminal_error, "insn ").and_then(|pc| usize::try_from(pc).ok())
    else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, terminal_line);
    let Some(instruction) =
        instruction_site_before_line(context.log, reported_pc, fragment_start, terminal_line)
    else {
        return false;
    };
    if call_target_from_instruction_tail(instruction.tail).is_none() {
        return false;
    }
    validation_seen(context.log, instruction.line, terminal_line)
}

fn exception_callback_return_contract_mismatch(context: &ProofSignalContext<'_>) -> bool {
    let Some(terminal_line) = context.terminal_line else {
        return false;
    };
    let Some(required_range) = terminal_required_return_range(context.terminal_error) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, terminal_line);
    let Some(validation_start) =
        active_validation_start(context.log, fragment_start, terminal_line)
    else {
        return false;
    };
    latest_reg_state_in_line_range_before(
        context.states,
        validation_start,
        terminal_line,
        context.terminal_pc,
        0,
    )
    .is_some_and(|state| scalar_state_outside_required_range(state, required_range))
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

fn latest_reg_state_in_line_range_before(
    states: &[VerifierInsn],
    start_line: usize,
    before_line: usize,
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<&RegState> {
    states
        .iter()
        .filter(|state| state.log_line >= start_line)
        .filter(|state| state.log_line < before_line)
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .filter_map(|state| state.regs.get(&reg))
        .next()
}

fn active_validation_start(log: &str, start_line: usize, before_line: usize) -> Option<usize> {
    let mut active = None;
    for (idx, line) in log
        .lines()
        .enumerate()
        .skip(start_line.saturating_sub(1))
        .take(before_line.saturating_sub(start_line))
    {
        let line = line.trim();
        if validating_function_name(line).is_some() {
            active = Some(idx + 1);
        } else if validation_success_line(line) {
            active = None;
        }
    }
    active
}

fn validating_function_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("Validating ")?;
    let (name, _) = rest.split_once("() func#")?;
    (!name.is_empty()).then_some(name)
}

fn validation_seen(log: &str, start_line: usize, before_line: usize) -> bool {
    log.lines()
        .skip(start_line.saturating_sub(1))
        .take(before_line.saturating_sub(start_line))
        .any(|line| validating_function_name(line.trim()).is_some())
}

fn validation_success_line(line: &str) -> bool {
    line.starts_with("Func#") && line.contains(" is safe for any args")
}

fn sleepable_call_in_non_sleepable_context(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("may sleep")
        && !terminal.contains("sleepable helper")
        && !terminal.contains("non-sleepable")
    {
        return false;
    }
    if !terminal.contains("non-sleepable") && !terminal.contains("preempt-disabled") {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !instruction.tail.contains("call ") {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    prior_non_sleepable_state(context.log, fragment_start, instruction.line)
}

fn prior_non_sleepable_state(log: &str, start_line: usize, before_line: usize) -> bool {
    let mut irq_save_depth = 0u32;
    for line in log
        .lines()
        .skip(start_line.saturating_sub(1))
        .take(before_line.saturating_sub(start_line))
    {
        let Some((_, tail)) = parse_instruction_line(line) else {
            continue;
        };
        let Some(target) = call_target_from_instruction_tail(tail) else {
            continue;
        };
        match target {
            "bpf_local_irq_save" | "bpf_rcu_read_lock" => {
                irq_save_depth = irq_save_depth.saturating_add(1);
            }
            "bpf_local_irq_restore" | "bpf_rcu_read_unlock" => {
                irq_save_depth = irq_save_depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    irq_save_depth > 0
}

fn modern_bpf_object_protocol_violation(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if !modern_bpf_object_protocol_target(target) {
        return false;
    }
    let Some(reg) = modern_bpf_object_protocol_register(&terminal, target, context.register) else {
        return false;
    };
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some(state) = latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        reg,
    ) else {
        return false;
    };

    if terminal.contains("has no valid kptr") {
        return target == "bpf_kptr_xchg" && invalid_kptr_storage_state(state);
    }
    if terminal.contains("must be a rcu pointer") {
        return modern_bpf_object_pointer_state(state)
            && !state.reg_type.starts_with("rcu_ptr")
            && !state.reg_type.starts_with("trusted_ptr");
    }
    if terminal.contains("must be referenced or trusted") {
        return modern_bpf_object_pointer_state(state) && !referenced_or_trusted_state(state);
    }
    if terminal.contains("pointer type struct") && terminal.contains("must point to scalar") {
        return target.starts_with("bpf_cgroup_") && state.reg_type == "fp";
    }
    if terminal.contains("expected pointer to struct") {
        return modern_bpf_object_pointer_state(state);
    }
    if terminal.contains("type=scalar expected=fp")
        || terminal.contains("memory, len pair leads to invalid memory access")
    {
        return target == "bpf_cpumask_populate" && state.reg_type == "scalar";
    }
    false
}

fn modern_bpf_object_protocol_target(target: &str) -> bool {
    target.starts_with("bpf_cgroup_")
        || target.starts_with("bpf_cpumask_")
        || target == "bpf_kptr_xchg"
        || target == "bpf_dynptr_from_skb"
}

fn modern_bpf_object_protocol_register(
    terminal: &str,
    target: &str,
    fallback: Option<u8>,
) -> Option<u8> {
    fallback
        .or_else(|| parse_arg_register_after(terminal, "args#"))
        .or_else(|| parse_arg_register_after(terminal, "arg#"))
        .or_else(|| {
            (target == "bpf_kptr_xchg" && terminal.contains("has no valid kptr")).then_some(1)
        })
}

fn parse_arg_register_after(message: &str, needle: &str) -> Option<u8> {
    let arg = parse_u32_after(message, needle)?;
    if arg >= 5 {
        return None;
    }
    u8::try_from(arg + 1).ok()
}

fn modern_bpf_object_pointer_state(state: &RegState) -> bool {
    state.reg_type == "fp"
        || state.reg_type == "scalar"
        || state.reg_type.starts_with("ptr_")
        || state.reg_type.starts_with("rcu_ptr")
        || state.reg_type.starts_with("untrusted_ptr")
        || state.reg_type.starts_with("trusted_ptr")
}

fn referenced_or_trusted_state(state: &RegState) -> bool {
    state.reg_type.starts_with("trusted_ptr") || state.reg_type.contains("ref_obj_id")
}

fn invalid_kptr_storage_state(state: &RegState) -> bool {
    state.reg_type == "map_value" || state.reg_type == "fp" || state.reg_type == "scalar"
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

fn btf_func_info_missing(context: &ProofSignalContext<'_>) -> bool {
    if !context
        .terminal_error
        .eq_ignore_ascii_case("missing btf func_info")
    {
        return false;
    }
    log_contains_subprogram(context.log) || log_contains_subprogram_relocation(context.log)
}

fn subprogram_reference_metadata_missing(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("caller passes invalid args into func") {
        return false;
    }
    let terminal_has_unknown_reference_size = terminal.contains("reference type('unknown")
        && terminal.contains("size cannot be determined");
    if !terminal_has_unknown_reference_size
        && !terminal_error_has_nearby_prior_line(context.log, context.terminal_error, 3, |line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("reference type('unknown") && lower.contains("size cannot be determined")
        })
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
    let Some(arg_index) = subprogram_argument_index(context.terminal_error) else {
        return false;
    };
    let Some(argument) = call_argument(&rejected.text, callee, arg_index as usize) else {
        return false;
    };
    let Some(arg_reg) = subprogram_argument_register(arg_index) else {
        return false;
    };
    if source_argument_erases_reference_metadata(&argument) {
        return true;
    }
    is_bare_identifier_argument(&argument)
        && latest_reg_state_before_instruction(context.states, instruction, fragment_start, arg_reg)
            .is_some_and(|state| state.reg_type == "ctx")
}

fn log_contains_subprogram(log: &str) -> bool {
    log.lines()
        .any(|line| line.trim_start().starts_with("func#1 @"))
}

fn log_contains_subprogram_relocation(log: &str) -> bool {
    log.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("points to subprog")
            || lower.contains("added ") && lower.contains("sub-prog")
    })
}

fn source_argument_erases_reference_metadata(argument: &str) -> bool {
    let compact = argument
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    compact.contains("(void*)") || compact == "void*"
}

fn subprogram_argument_index(terminal_error: &str) -> Option<u32> {
    let arg = parse_u32_after(terminal_error, "arg#")?;
    (arg < 5).then_some(arg)
}

fn subprogram_argument_register(arg_index: u32) -> Option<u8> {
    if arg_index >= 5 {
        return None;
    }
    u8::try_from(arg_index + 1).ok()
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

fn unreadable_program_entry_argument(context: &ProofSignalContext<'_>) -> bool {
    let Some((reg, instruction, fragment_start)) = unreadable_register_terminal_site(context)
    else {
        return false;
    };
    unreadable_entry_argument(context, instruction, fragment_start, reg)
}

fn unreadable_helper_argument(context: &ProofSignalContext<'_>) -> bool {
    let Some((reg, instruction, _)) = unreadable_register_terminal_site(context) else {
        return false;
    };
    unreadable_helper_call_argument(instruction, reg)
}

fn unreadable_return_register(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::StackInitialized
        || !context.terminal_error.contains("!read_ok")
        || context.register != Some(0)
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !instruction_is_bpf_exit(instruction.tail) {
        return false;
    }
    true
}

fn legacy_skb_load_unreadable_register(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::StackInitialized
        || !context.terminal_error.contains("!read_ok")
        || context.register != Some(6)
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !legacy_skb_load_instruction(instruction.tail) {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(1);
    verifier_path_snapshot_before_instruction(context.branch_states, instruction, fragment_start)
        .is_some_and(|snapshot| !snapshot.regs.contains_key(&6))
}

fn legacy_skb_load_instruction(tail: &str) -> bool {
    let mut tokens = tail.split_whitespace();
    let Some(opcode) = tokens.next() else {
        return false;
    };
    if !matches!(opcode, "(20)" | "(28)" | "(30)" | "(40)" | "(48)" | "(50)") {
        return false;
    }
    let compact: String = tail.split_whitespace().collect();
    compact.contains("=*(u") && compact.contains("*)skb[")
}

fn unreadable_register_terminal_site<'a>(
    context: &'a ProofSignalContext<'a>,
) -> Option<(u8, TerminalInstruction<'a>, usize)> {
    if context.obligation != ProofObligation::StackInitialized
        || !context.terminal_error.contains("!read_ok")
    {
        return None;
    }
    let reg = context.register?;
    if reg == 0 {
        return None;
    }
    let instruction =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)?;
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(1);
    if latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
        .is_some()
    {
        return None;
    }
    Some((reg, instruction, fragment_start))
}

fn unreadable_helper_call_argument(instruction: TerminalInstruction<'_>, reg: u8) -> bool {
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    target == "bpf_skb_store_bytes" && reg == 5
}

fn map_pointer_raw_access_contract(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::HelperArgument
        || !context
            .terminal_error
            .contains("only read from bpf_array is supported")
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
    let Some(snapshot) = verifier_path_snapshot_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
    ) else {
        return false;
    };
    snapshot
        .regs
        .get(&base_reg)
        .is_some_and(|state| state.reg_type == "map_ptr")
}

fn perf_event_output_packet_access(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::HelperArgument
        || !context
            .terminal_error
            .contains("helper access to the packet is not allowed")
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if call_target_from_instruction_tail(instruction.tail) != Some("bpf_perf_event_output") {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some(snapshot) = verifier_path_snapshot_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
    ) else {
        return false;
    };
    let Some(data) = snapshot.regs.get(&4) else {
        return false;
    };
    let Some(size) = snapshot.regs.get(&5) else {
        return false;
    };
    matches!(data.reg_type.as_str(), "pkt" | "pkt_meta") && size.reg_type == "scalar"
}

fn helper_stack_read_exceeds_initialized_range(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::StackInitialized {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("read from stack") || !terminal.contains("memory, len pair") {
        return false;
    }
    let Some(access) = parse_stack_read_access(context.terminal_error) else {
        return false;
    };
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some((pointer_reg, len_reg)) = helper_stack_read_signature(target) else {
        return false;
    };
    if access.reg != pointer_reg {
        return false;
    }
    if context.register.is_some_and(|reg| reg != pointer_reg) {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some(snapshot) = verifier_path_snapshot_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
    ) else {
        return false;
    };
    let Some(pointer_state) = snapshot.regs.get(&pointer_reg) else {
        return false;
    };
    if pointer_state.reg_type != "fp" {
        return false;
    }
    let pointer_frame = pointer_state.source_frame.unwrap_or(snapshot.frame);
    if pointer_frame != snapshot.frame {
        return false;
    }
    let Some(len) = helper_stack_read_length_from_snapshot(&snapshot, len_reg) else {
        return false;
    };
    if access.size != len || access.delta < 0 {
        return false;
    }
    let Some(start) = pointer_state
        .offset
        .and_then(|offset| i16::try_from(offset).ok())
    else {
        return false;
    };
    if i64::from(start) != access.base_off {
        return false;
    }
    if u64::try_from(access.delta)
        .ok()
        .is_none_or(|delta| delta >= len)
    {
        return false;
    }
    len > u64::try_from(initialized_stack_bytes_from_snapshot(
        &snapshot.stack,
        start,
    ))
    .unwrap_or(0)
}

fn helper_stack_read_signature(target: &str) -> Option<(u8, u8)> {
    match target {
        "bpf_dynptr_slice" | "bpf_dynptr_slice_rdwr" => Some((3, 4)),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StackReadAccess {
    reg: u8,
    base_off: i64,
    delta: i64,
    size: u64,
}

fn parse_stack_read_access(message: &str) -> Option<StackReadAccess> {
    message.split(';').find_map(parse_stack_read_access_segment)
}

fn parse_stack_read_access_segment(segment: &str) -> Option<StackReadAccess> {
    let tokens: Vec<_> = segment.split_whitespace().collect();
    for window in tokens.windows(9) {
        if window[0] != "invalid"
            || window[1] != "read"
            || window[2] != "from"
            || window[3] != "stack"
            || window[5] != "off"
            || window[7] != "size"
        {
            continue;
        }
        let reg = window[4].strip_prefix('R')?.parse().ok()?;
        let (base_off, delta) = parse_stack_offset_delta(window[6])?;
        let size = window[8].parse().ok()?;
        return Some(StackReadAccess {
            reg,
            base_off,
            delta,
            size,
        });
    }
    None
}

fn parse_stack_offset_delta(expression: &str) -> Option<(i64, i64)> {
    let split = expression
        .char_indices()
        .skip(1)
        .find_map(|(idx, ch)| matches!(ch, '+' | '-').then_some(idx));
    let Some(split) = split else {
        return Some((expression.parse().ok()?, 0));
    };
    Some((
        expression[..split].parse().ok()?,
        expression[split..].parse().ok()?,
    ))
}

fn helper_stack_read_length_from_snapshot(
    snapshot: &PathVerifierSnapshot,
    len_reg: u8,
) -> Option<u64> {
    let state = snapshot.regs.get(&len_reg)?;
    state
        .exact_u64()
        .or_else(|| state.exact_u32().map(u64::from))
}

fn verifier_path_snapshot_before_instruction(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> Option<PathVerifierSnapshot> {
    let mut snapshot: Option<PathVerifierSnapshot> = None;
    for state in states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
    {
        let reset_path = matches!(
            state.kind,
            VerifierInsnKind::EdgeFullState | VerifierInsnKind::PcFullState
        ) || snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.frame != state.frame);
        if reset_path || snapshot.is_none() {
            snapshot = Some(PathVerifierSnapshot {
                frame: state.frame,
                regs: state.regs.clone(),
                stack: state.stack.clone(),
            });
            continue;
        }
        let snapshot = snapshot.as_mut()?;
        snapshot.regs.extend(state.regs.clone());
        snapshot.stack.extend(state.stack.clone());
    }
    snapshot
}

fn initialized_stack_bytes_from_snapshot(stack: &HashMap<i16, StackState>, start: i16) -> i16 {
    if start >= 0 {
        return 0;
    }
    let mut initialized = 0i16;
    let mut offset = start;
    while offset < 0 {
        if !stack_byte_initialized_at_offset(stack, offset) {
            break;
        }
        initialized = initialized.saturating_add(1);
        offset = offset.saturating_add(1);
    }
    initialized
}

fn stack_byte_initialized_at_offset(
    stack: &HashMap<i16, StackState>,
    absolute_offset: i16,
) -> bool {
    let Some(slot_start) = verifier_stack_slot_start(absolute_offset) else {
        return false;
    };
    stack
        .get(&slot_start)
        .is_some_and(|slot| stack_byte_initialized(slot, slot_start, absolute_offset))
}

fn stack_byte_initialized(stack: &StackState, slot_start: i16, absolute_offset: i16) -> bool {
    if let Some(slot_types) = stack.slot_types.as_deref() {
        let byte_index = absolute_offset.saturating_sub(slot_start);
        let Ok(byte_index) = usize::try_from(byte_index) else {
            return false;
        };
        if byte_index >= 8 {
            return false;
        }
        return slot_types
            .as_bytes()
            .get(7 - byte_index)
            .is_some_and(|slot_type| plain_stack_slot_byte(*slot_type, stack.value.as_ref()));
    }
    stack
        .value
        .as_ref()
        .is_some_and(plain_helper_readable_stack_value)
}

fn plain_stack_slot_byte(slot_type: u8, value: Option<&RegState>) -> bool {
    match slot_type {
        b'0' | b'm' => true,
        b'r' => value.is_some_and(plain_helper_readable_stack_value),
        _ => false,
    }
}

fn plain_helper_readable_stack_value(value: &RegState) -> bool {
    value.reg_type == "scalar"
}

fn verifier_stack_slot_start(absolute_offset: i16) -> Option<i16> {
    if absolute_offset >= 0 {
        return None;
    }
    let slot_index = ((-i32::from(absolute_offset) - 1) / 8) + 1;
    i16::try_from(-slot_index * 8).ok()
}

fn unreadable_entry_argument(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: u8,
) -> bool {
    if reg < 2 {
        return false;
    }
    if !terminal_instruction_uses_register(instruction.tail, reg) {
        return false;
    }
    let Some(entry_state) = context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.pc == 0)
        .find(|state| state.regs.get(&1).is_some_and(|reg| reg.reg_type == "ctx"))
    else {
        return false;
    };
    if entry_state.regs.contains_key(&reg) {
        return false;
    }
    context
        .source_events
        .iter()
        .filter(|event| event.log_line >= fragment_start)
        .any(|event| event.pc == Some(0) && looks_like_multi_argument_bpf_entry(&event.source.text))
}

fn terminal_instruction_uses_register(tail: &str, reg: u8) -> bool {
    let needle = format!("r{reg}");
    tail.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token == needle)
}

fn looks_like_multi_argument_bpf_entry(text: &str) -> bool {
    let trimmed = text.trim_start();
    let looks_like_function = trimmed.starts_with("int ")
        || trimmed.starts_with("long ")
        || trimmed.contains("BPF_PROG(")
        || trimmed.contains("BPF_KPROBE(");
    looks_like_function && trimmed.contains('(') && trimmed.contains(',')
}

fn helper_stack_write_beyond_frame(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::StackInitialized {
        return false;
    }
    let Some(access) = stack_write_access_range(context.terminal_error) else {
        return false;
    };
    if bpf_stack_frame_contains(access) {
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
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some((write_reg, len_reg)) = helper_writable_stack_signature(target) else {
        return false;
    };
    if reg != write_reg {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(1);
    let Some(arg) =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
    else {
        return false;
    };
    if arg.reg_type != "fp" || arg.offset != Some(i32::from(access.start)) {
        return false;
    }
    helper_write_size_argument_matches(context, instruction, fragment_start, len_reg, access)
}

fn helper_writable_stack_signature(target: &str) -> Option<(u8, u8)> {
    match target {
        "bpf_get_current_comm" => Some((1, 2)),
        _ => None,
    }
}

fn helper_write_size_argument_matches(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    len_reg: u8,
    access: StackByteRange,
) -> bool {
    let Some(size_arg) =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, len_reg)
    else {
        return false;
    };
    size_arg.exact_u64() == Some(access.len() as u64)
        || size_arg.exact_u32() == Some(access.len() as u32)
}

fn stack_write_access_range(message: &str) -> Option<StackByteRange> {
    message
        .to_ascii_lowercase()
        .contains("invalid write to stack")
        .then(|| {
            let offset = parse_signed_i16_after(message, "off=")
                .or_else(|| parse_signed_i16_after(message, "off "))?;
            let size = parse_signed_i16_after(message, "size=")
                .or_else(|| parse_signed_i16_after(message, "size "))?;
            let end = offset.checked_add(size)?;
            Some(StackByteRange { start: offset, end })
        })
        .flatten()
}

fn bpf_stack_frame_contains(access: StackByteRange) -> bool {
    const BPF_STACK_MIN_OFFSET: i16 = -512;
    BPF_STACK_MIN_OFFSET <= access.start && access.end <= 0
}

fn dynptr_stack_storage_access(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::StackInitialized | ProofObligation::Unknown
    ) {
        return false;
    }
    if rejected_source(context.events).is_some_and(|source| {
        source.text.contains("bpf_dynptr_slice")
            && context.terminal_error.contains("memory, len pair")
    }) {
        return false;
    }
    let Some(access) = stack_access_range_from_context(context) else {
        return false;
    };
    latest_stack_value_overlap(context, access, 16, |value| {
        value.reg_type.starts_with("dynptr")
    })
    .unwrap_or(false)
}

fn dynptr_stack_slot_write_overlap(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::DynptrSafety
            | ProofObligation::HelperArgument
            | ProofObligation::StackInitialized
            | ProofObligation::Unknown
    ) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("potential write to dynptr")
    {
        return false;
    }
    let Some(offset) = parse_signed_i16_after(context.terminal_error, "off=") else {
        return false;
    };
    let Some(access) = stack_value_range(offset, 1) else {
        return false;
    };
    latest_stack_value_overlap(context, access, 16, |value| {
        value.reg_type.starts_with("dynptr")
    })
    .unwrap_or(false)
}

fn dynptr_protocol_signal_obligation(obligation: ProofObligation) -> bool {
    matches!(
        obligation,
        ProofObligation::DynptrSafety
            | ProofObligation::HelperArgument
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::StackInitialized
            | ProofObligation::TypeContract
            | ProofObligation::Unknown
    )
}

fn dynptr_uninitialized_argument(context: &ProofSignalContext<'_>) -> bool {
    if !dynptr_protocol_signal_obligation(context.obligation) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("expected an initialized dynptr")
    {
        return false;
    }
    dynptr_initialized_argument_missing(context)
}

fn dynptr_referenced_slot_overwrite(context: &ProofSignalContext<'_>) -> bool {
    if !dynptr_protocol_signal_obligation(context.obligation) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("cannot overwrite referenced dynptr")
    {
        return false;
    }
    dynptr_referenced_stack_slot_overwrite(context)
}

fn dynptr_readonly_packet_write(context: &ProofSignalContext<'_>) -> bool {
    if !dynptr_protocol_signal_obligation(context.obligation) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("does not allow writes to packet data")
    {
        return false;
    }
    dynptr_packet_rdwr_disallowed(context)
}

fn dynptr_initialized_argument_missing(context: &ProofSignalContext<'_>) -> bool {
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(arg_reg) = dynptr_initialized_arg(target) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        arg_reg,
    ) else {
        return false;
    };
    if !is_stable_dynptr_stack_arg(arg) {
        return false;
    }
    dynptr_stack_slot_relation(context, instruction, fragment_start, arg, arg_frame).is_none()
}

fn dynptr_referenced_stack_slot_overwrite(context: &ProofSignalContext<'_>) -> bool {
    if let Some(instruction) = terminal_call_instruction_site(context) {
        let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
        if dynptr_initializer_overwrites_referenced_slot(context, instruction, fragment_start) {
            return true;
        }
    }
    dynptr_plain_write_overlaps_referenced_slot(context)
}

fn dynptr_initializer_overwrites_referenced_slot(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> bool {
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(arg_reg) = dynptr_initializer_output_arg(target) else {
        return false;
    };
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        arg_reg,
    ) else {
        return false;
    };
    if dynptr_stack_slot_relation(context, instruction, fragment_start, arg, arg_frame)
        != Some(DynptrStackSlotRelation::Exact)
    {
        return false;
    }
    dynptr_slot_has_live_ref_before_instruction(
        context,
        instruction,
        fragment_start,
        arg.offset,
        arg_frame,
    )
}

fn dynptr_plain_write_overlaps_referenced_slot(context: &ProofSignalContext<'_>) -> bool {
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some((access, frame)) =
        terminal_stack_memory_write_range_with_frame(context, instruction, fragment_start)
    else {
        return false;
    };
    latest_live_ref_dynptr_stack_overlap_before_instruction(
        context,
        instruction,
        fragment_start,
        access,
        frame,
    )
    .unwrap_or(false)
}

fn dynptr_packet_rdwr_disallowed(context: &ProofSignalContext<'_>) -> bool {
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if target != "bpf_dynptr_slice_rdwr" {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some(slot) =
        dynptr_stack_slot_for_call_argument(context.branch_states, instruction, fragment_start, 1)
    else {
        return false;
    };
    dynptr_slot_backing_before(context, slot, instruction.line) == Some(DynptrBacking::Packet)
}

fn dynptr_helper_argument_state_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::DynptrSafety
            | ProofObligation::HelperArgument
            | ProofObligation::TypeContract
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);

    if dynptr_initializer_output_slot_mismatch(context, instruction, fragment_start, target) {
        return true;
    }
    if dynptr_from_mem_backing_memory_mismatch(context, instruction, fragment_start, target) {
        return true;
    }
    dynptr_live_argument_interior_pointer(context, instruction, fragment_start, target)
}

fn dynptr_slice_variable_length(context: &ProofSignalContext<'_>) -> bool {
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if !matches!(target, "bpf_dynptr_slice" | "bpf_dynptr_slice_rdwr") {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some(length) = latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        4,
    ) else {
        return false;
    };
    length.reg_type == "scalar" && length.exact_value.is_none()
}

fn dynptr_initializer_output_slot_mismatch(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
) -> bool {
    let Some(arg_reg) = dynptr_initializer_output_arg(target) else {
        return false;
    };
    let Some(arg) = latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        arg_reg,
    ) else {
        return false;
    };
    !is_stable_dynptr_stack_arg(arg)
}

fn dynptr_from_mem_backing_memory_mismatch(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
) -> bool {
    if target != "bpf_dynptr_from_mem" {
        return false;
    }
    latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        1,
    )
    .is_some_and(|arg| arg.reg_type == "fp")
}

fn dynptr_live_argument_interior_pointer(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
) -> bool {
    let Some(arg_reg) = dynptr_live_arg(target) else {
        return false;
    };
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        arg_reg,
    ) else {
        return false;
    };
    dynptr_stack_slot_relation(context, instruction, fragment_start, arg, arg_frame)
        == Some(DynptrStackSlotRelation::Interior)
}

fn dynptr_release_unacquired_reference(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::DynptrSafety
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::HelperArgument
            | ProofObligation::Unknown
    ) {
        return false;
    }
    if !context
        .terminal_error
        .to_ascii_lowercase()
        .contains("unacquired reference")
    {
        return false;
    }
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if !matches!(
        target,
        "bpf_ringbuf_discard_dynptr" | "bpf_ringbuf_submit_dynptr"
    ) {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        1,
    ) else {
        return false;
    };
    if dynptr_stack_slot_relation(context, instruction, fragment_start, arg, arg_frame)
        != Some(DynptrStackSlotRelation::Exact)
    {
        return false;
    }
    latest_verifier_state_before_instruction(context.states, instruction, fragment_start)
        .is_some_and(|state| state.refs.unwrap_or(0) == 0)
}

fn dynptr_initializer_output_arg(target: &str) -> Option<u8> {
    match target {
        "bpf_ringbuf_reserve_dynptr" | "bpf_dynptr_from_mem" => Some(4),
        "bpf_dynptr_from_skb" | "bpf_dynptr_from_xdp" => Some(3),
        _ => None,
    }
}

fn dynptr_live_arg(target: &str) -> Option<u8> {
    match target {
        "bpf_dynptr_data"
        | "bpf_dynptr_clone"
        | "bpf_ringbuf_discard_dynptr"
        | "bpf_ringbuf_submit_dynptr" => Some(1),
        "bpf_dynptr_read" | "bpf_dynptr_write" => Some(3),
        _ => None,
    }
}

fn dynptr_initialized_arg(target: &str) -> Option<u8> {
    match target {
        "bpf_dynptr_data"
        | "bpf_dynptr_clone"
        | "bpf_dynptr_slice"
        | "bpf_dynptr_slice_rdwr"
        | "bpf_ringbuf_discard_dynptr"
        | "bpf_ringbuf_submit_dynptr" => Some(1),
        "bpf_dynptr_read" | "bpf_dynptr_write" => Some(3),
        _ => None,
    }
}

fn dynptr_slot_has_live_ref_before_instruction(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    offset: Option<i32>,
    frame: usize,
) -> bool {
    let Some(offset) = offset.and_then(|offset| i16::try_from(offset).ok()) else {
        return false;
    };
    context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .filter(|state| state.frame == frame)
        .rev()
        .find_map(|state| {
            let stack = state.stack.get(&offset)?;
            Some(dynptr_stack_slot_has_live_ref(stack, state))
        })
        .unwrap_or(false)
}

fn dynptr_stack_slot_has_live_ref(stack: &StackState, state: &VerifierInsn) -> bool {
    let Some(value) = stack.value.as_ref() else {
        return false;
    };
    value.reg_type.starts_with("dynptr")
        && value
            .ref_id
            .is_some_and(|ref_id| state.ref_ids.contains(&ref_id))
}

fn is_stable_dynptr_stack_arg(arg: &RegState) -> bool {
    arg.reg_type == "fp"
        && arg.offset.is_some_and(|offset| offset < 0)
        && !reg_state_has_variable_offset(arg)
}

fn reg_state_has_variable_offset(state: &RegState) -> bool {
    state.tnum.is_some()
        || state.range.smin.is_some()
        || state.range.smax.is_some()
        || state.range.umin.is_some()
        || state.range.umax.is_some()
        || state.range.smin32.is_some()
        || state.range.smax32.is_some()
        || state.range.umin32.is_some()
        || state.range.umax32.is_some()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DynptrStackSlotRelation {
    Exact,
    Interior,
}

fn dynptr_stack_slot_relation(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    arg: &RegState,
    arg_frame: usize,
) -> Option<DynptrStackSlotRelation> {
    if arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
        return None;
    }
    let offset = i16::try_from(arg.offset?).ok()?;
    let access = stack_value_range(offset, 16)?;
    for state in context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .rev()
    {
        let mut saw_overlapping_stack_state = false;
        if state.frame != arg_frame {
            continue;
        }
        for (slot_offset, stack) in &state.stack {
            let is_dynptr = stack
                .value
                .as_ref()
                .is_some_and(|value| value.reg_type.starts_with("dynptr"));
            let Some(slot_range) = stack_value_range(*slot_offset, if is_dynptr { 16 } else { 8 })
            else {
                continue;
            };
            if !slot_range.overlaps(access) {
                continue;
            }
            saw_overlapping_stack_state = true;
            if !is_dynptr {
                continue;
            }
            if *slot_offset == offset {
                return Some(DynptrStackSlotRelation::Exact);
            }
            if slot_range.contains(offset) {
                return Some(DynptrStackSlotRelation::Interior);
            }
        }
        if saw_overlapping_stack_state {
            return None;
        }
    }
    None
}

fn iterator_stack_storage_access(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::StackInitialized | ProofObligation::Unknown
    ) {
        return false;
    }
    let Some(access) = stack_access_range_from_context(context) else {
        return false;
    };
    latest_stack_value_overlap(context, access, 8, |value| {
        value.reg_type.starts_with("iter_")
    })
    .unwrap_or(false)
}

#[derive(Clone, Copy)]
enum IteratorArg0Requirement {
    EmptyStackSlot,
    LiveIteratorStackSlot,
}

fn iterator_helper_argument_state_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::IteratorLifecycle
            | ProofObligation::HelperArgument
            | ProofObligation::StackInitialized
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(requirement) = iterator_arg0_requirement(target) else {
        return false;
    };
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        1,
    ) else {
        return false;
    };
    match requirement {
        IteratorArg0Requirement::EmptyStackSlot => {
            if arg.reg_type != "fp" {
                return true;
            }
            iterator_stack_slot_state(context, arg).is_some()
        }
        IteratorArg0Requirement::LiveIteratorStackSlot => {
            if arg.reg_type != "fp" {
                return true;
            }
            match iterator_live_stack_slot_state(
                context,
                instruction,
                fragment_start,
                arg,
                arg_frame,
            ) {
                Some(IteratorLiveStackSlotState::LiveIterator) => false,
                Some(IteratorLiveStackSlotState::OrdinaryBytes) => true,
                Some(IteratorLiveStackSlotState::ConsumedIterator) => context
                    .terminal_error
                    .to_ascii_lowercase()
                    .contains("expected an initialized iter"),
                None => false,
            }
        }
    }
}

fn iterator_arg0_requirement(target: &str) -> Option<IteratorArg0Requirement> {
    if !target.starts_with("bpf_iter_") {
        return None;
    }
    if target.ends_with("_new") {
        return Some(IteratorArg0Requirement::EmptyStackSlot);
    }
    if target.ends_with("_next") || target.ends_with("_destroy") {
        return Some(IteratorArg0Requirement::LiveIteratorStackSlot);
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IteratorStackSlotState {
    LiveIterator,
    OrdinaryBytes,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IteratorLiveStackSlotState {
    LiveIterator,
    ConsumedIterator,
    OrdinaryBytes,
}

fn iterator_stack_slot_state(
    context: &ProofSignalContext<'_>,
    arg: &RegState,
) -> Option<IteratorStackSlotState> {
    let offset = i16::try_from(arg.offset?).ok()?;
    let range = stack_value_range(offset, 8)?;
    latest_stack_value_overlap(context, range, 8, |value| {
        value.reg_type.starts_with("iter_")
    })
    .map(|has_iterator| {
        if has_iterator {
            IteratorStackSlotState::LiveIterator
        } else {
            IteratorStackSlotState::OrdinaryBytes
        }
    })
}

fn iterator_live_stack_slot_state(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    arg: &RegState,
    arg_frame: usize,
) -> Option<IteratorLiveStackSlotState> {
    let offset = i16::try_from(arg.offset?).ok()?;
    let access = stack_value_range(offset, 8)?;
    let current_state =
        latest_verifier_state_before_instruction(context.states, instruction, fragment_start);
    for state in context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .filter(|state| state.frame == arg_frame)
        .rev()
    {
        let mut saw_overlap = false;
        for (slot_offset, stack) in &state.stack {
            let is_iterator = stack
                .value
                .as_ref()
                .is_some_and(|value| value.reg_type.starts_with("iter_"));
            let Some(range) = stack_value_range(*slot_offset, 8) else {
                continue;
            };
            if !range.overlaps(access) {
                continue;
            }
            saw_overlap = true;
            if !is_iterator {
                continue;
            }
            let live = stack
                .value
                .as_ref()
                .and_then(|value| value.ref_id)
                .is_some_and(|ref_id| {
                    current_state.is_some_and(|state| state.ref_ids.contains(&ref_id))
                });
            return Some(if live {
                IteratorLiveStackSlotState::LiveIterator
            } else {
                IteratorLiveStackSlotState::ConsumedIterator
            });
        }
        if saw_overlap {
            return Some(IteratorLiveStackSlotState::OrdinaryBytes);
        }
    }
    None
}

#[derive(Clone, Copy)]
enum IrqFlagArg0Requirement {
    EmptyStackSlot,
    LiveIrqFlagSlot,
}

fn irq_flag_state_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::LockState
            | ProofObligation::HelperArgument
            | ProofObligation::StackInitialized
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(requirement) = irq_flag_arg0_requirement(target) else {
        return false;
    };
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        1,
    ) else {
        return false;
    };
    match requirement {
        IrqFlagArg0Requirement::EmptyStackSlot => {
            if arg.reg_type != "fp" {
                return true;
            }
            irq_flag_stack_slot_state(context, arg, arg_frame).is_some()
        }
        IrqFlagArg0Requirement::LiveIrqFlagSlot => {
            if arg.reg_type != "fp" {
                return true;
            }
            irq_flag_stack_slot_state(context, arg, arg_frame)
                .is_some_and(|state| state == IrqFlagStackSlotState::OrdinaryBytes)
        }
    }
}

fn irq_flag_arg0_requirement(target: &str) -> Option<IrqFlagArg0Requirement> {
    match target {
        "bpf_local_irq_save" => Some(IrqFlagArg0Requirement::EmptyStackSlot),
        "bpf_local_irq_restore" => Some(IrqFlagArg0Requirement::LiveIrqFlagSlot),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IrqFlagStackSlotState {
    LiveIrqFlag,
    OrdinaryBytes,
}

fn irq_flag_stack_slot_state(
    context: &ProofSignalContext<'_>,
    arg: &RegState,
    arg_frame: usize,
) -> Option<IrqFlagStackSlotState> {
    let offset = i16::try_from(arg.offset?).ok()?;
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or(0);
    for state in context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.frame == arg_frame)
        .filter(|state| context.terminal_pc.is_none_or(|pc| state.pc <= pc))
        .filter(|state| {
            context
                .terminal_line
                .is_none_or(|line| state.log_line < line)
        })
        .rev()
    {
        if let Some(stack) = state.stack.get(&offset) {
            return Some(if is_irq_flag_stack_slot(stack) {
                IrqFlagStackSlotState::LiveIrqFlag
            } else {
                IrqFlagStackSlotState::OrdinaryBytes
            });
        }
        if state.stack.iter().any(|(slot_offset, _)| {
            stack_value_range(*slot_offset, 8).is_some_and(|range| range.contains(offset))
        }) {
            return Some(IrqFlagStackSlotState::OrdinaryBytes);
        }
    }
    None
}

fn is_irq_flag_stack_slot(stack: &StackState) -> bool {
    stack.value.is_none() && stack.slot_types.as_deref() == Some("ffffffff")
}

fn irq_restore_order_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::LockState
            | ProofObligation::KfuncReference
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::HelperArgument
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !terminal.contains("cannot restore irq state out of order") {
        return false;
    }
    let Some(expected_ref_id) = parse_u32_after(&terminal, "expected id=") else {
        return false;
    };
    let Some(acquired_pc) =
        parse_u32_after(&terminal, "acquired at insn_idx=").and_then(|pc| usize::try_from(pc).ok())
    else {
        return false;
    };
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(flag_arg) = irq_restore_flag_argument(target) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some(acquired_instruction) =
        instruction_site_before_line(context.log, acquired_pc, fragment_start, instruction.line)
    else {
        return false;
    };
    let Some(acquired_target) = call_target_from_instruction_tail(acquired_instruction.tail) else {
        return false;
    };
    if !irq_save_target(acquired_target) {
        return false;
    }
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        flag_arg,
    ) else {
        return false;
    };
    if arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
        return false;
    }
    if irq_flag_stack_slot_state(context, arg, arg_frame)
        != Some(IrqFlagStackSlotState::LiveIrqFlag)
    {
        return false;
    }
    if target == "bpf_local_irq_restore" {
        return latest_ref_state_before_instruction(context.states, instruction, fragment_start)
            .is_some_and(|state| state.ref_ids.contains(&expected_ref_id));
    }
    target == "bpf_res_spin_unlock_irqrestore" && acquired_target == "bpf_res_spin_lock_irqsave"
}

fn irq_restore_flag_argument(target: &str) -> Option<u8> {
    match target {
        "bpf_local_irq_restore" => Some(1),
        "bpf_res_spin_unlock_irqrestore" => Some(2),
        _ => None,
    }
}

fn irq_save_target(target: &str) -> bool {
    matches!(target, "bpf_local_irq_save" | "bpf_res_spin_lock_irqsave")
}

fn irq_restore_helper_class_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::LockState
            | ProofObligation::KfuncReference
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::HelperArgument
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("function calls are not allowed") && terminal.contains("holding a lock"))
    {
        return false;
    }
    let Some(instruction) = terminal_call_instruction_site(context) else {
        return false;
    };
    let Some(restore_target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(flag_arg) = irq_restore_flag_argument(restore_target) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some((arg, arg_frame)) = latest_reg_state_for_call_argument_with_frame(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        flag_arg,
    ) else {
        return false;
    };
    if arg.reg_type != "fp" || reg_state_has_variable_offset(arg) {
        return false;
    }
    if irq_flag_stack_slot_state(context, arg, arg_frame)
        != Some(IrqFlagStackSlotState::LiveIrqFlag)
    {
        return false;
    }
    let Some(ref_state) =
        latest_verifier_state_before_instruction(context.states, instruction, fragment_start)
    else {
        return false;
    };
    let Some(newest_ref) = ref_state.ref_ids.last().copied() else {
        return false;
    };
    let Some(origin_target) = irq_ref_origin_for_stack_slot(
        context,
        fragment_start,
        instruction.line,
        newest_ref,
        arg,
        arg_frame,
    ) else {
        return false;
    };
    matches!(
        (restore_target, origin_target),
        ("bpf_local_irq_restore", "bpf_res_spin_lock_irqsave")
            | ("bpf_res_spin_unlock_irqrestore", "bpf_local_irq_save")
    )
}

fn irq_ref_origin_for_stack_slot<'a>(
    context: &'a ProofSignalContext<'_>,
    fragment_start: usize,
    before_line: usize,
    ref_id: u32,
    arg: &RegState,
    arg_frame: usize,
) -> Option<&'a str> {
    let offset = i16::try_from(arg.offset?).ok()?;
    context
        .states
        .iter()
        .rev()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.ref_ids.contains(&ref_id))
        .find_map(|state| {
            let target = call_target_on_log_line(context.log, state.log_line)?;
            if !irq_save_target(target) {
                return None;
            }
            if state.frame == arg_frame
                && state.stack.get(&offset).is_some_and(is_irq_flag_stack_slot)
            {
                return Some(target);
            }
            (irq_ref_stack_slot_linked_after_origin(
                context,
                fragment_start,
                state.log_line,
                before_line,
                ref_id,
                offset,
                arg_frame,
            ))
            .then_some(target)
        })
}

fn irq_ref_stack_slot_linked_after_origin(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    origin_line: usize,
    before_line: usize,
    ref_id: u32,
    offset: i16,
    frame: usize,
) -> bool {
    if irq_stack_slot_live_before_line(context, fragment_start, origin_line, offset, frame) {
        return false;
    }
    context
        .states
        .iter()
        .filter(|state| state.log_line > origin_line)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.frame == frame)
        .filter(|state| state.ref_ids.contains(&ref_id))
        .any(|state| state.stack.get(&offset).is_some_and(is_irq_flag_stack_slot))
}

fn irq_stack_slot_live_before_line(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    before_line: usize,
    offset: i16,
    frame: usize,
) -> bool {
    context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.frame == frame)
        .rev()
        .find_map(|state| state.stack.get(&offset))
        .is_some_and(is_irq_flag_stack_slot)
}

fn irq_state_live_at_exit(context: &ProofSignalContext<'_>) -> bool {
    if !matches!(
        context.obligation,
        ProofObligation::LockState
            | ProofObligation::KfuncReference
            | ProofObligation::ReferenceLifecycle
            | ProofObligation::Unknown
    ) {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("bpf_exit instruction") && terminal.contains("bpf_local_irq_save-ed")) {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if !instruction.tail.contains("exit") {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    let Some(exit_state) =
        latest_verifier_state_at_or_before_instruction(context.states, instruction, fragment_start)
    else {
        return false;
    };
    exit_state.ref_ids.iter().any(|ref_id| {
        irq_save_ref_origin_before_exit(context, fragment_start, instruction.line, *ref_id)
    })
}

fn irq_save_ref_origin_before_exit(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    before_line: usize,
    ref_id: u32,
) -> bool {
    context
        .states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.ref_ids.contains(&ref_id))
        .any(|state| {
            call_target_on_log_line(context.log, state.log_line).is_some_and(irq_save_target)
        })
}

fn call_target_on_log_line(log: &str, line_number: usize) -> Option<&str> {
    let line = log.lines().nth(line_number.checked_sub(1)?)?;
    let (_, tail) = parse_instruction_line(line.trim())?;
    call_target_from_instruction_tail(tail)
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, terminal_instruction.line));
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

fn nullable_pointer_use_without_proof(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::NullablePointer {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("_or_null") || terminal.contains("possibly null pointer")) {
        return false;
    }
    if terminal.contains("trusted arg") {
        return false;
    }
    let helper_arg_terminal = terminal.contains("helper arg");
    let Some(reg) = (if helper_arg_terminal {
        nullable_use_register(&terminal)
    } else {
        nullable_use_register(&terminal).or(context.register)
    }) else {
        return false;
    };
    let state = if let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    {
        if nullable_instruction_register_mismatch(&terminal, instruction.tail, reg) {
            return false;
        }
        let fragment_start = context
            .terminal_line
            .map(|line| verifier_fragment_start_line(context.log, line))
            .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, reg)
    } else {
        if helper_arg_terminal {
            return false;
        }
        latest_reg_state_before(context.states, context.terminal_pc, reg)
    };
    state.is_some_and(|state| {
        state.reg_type.contains("_or_null") && !is_trusted_nullable_state(state)
    })
}

fn nullable_use_register(terminal: &str) -> Option<u8> {
    parse_u32_after(terminal, "helper arg")
        .and_then(|reg| (1..=5).contains(&reg).then_some(reg as u8))
}

fn nullable_instruction_register_mismatch(terminal: &str, instruction_tail: &str, reg: u8) -> bool {
    if terminal.contains("helper arg") {
        return call_target_from_instruction_tail(instruction_tail).is_none();
    }
    if terminal.contains("invalid mem access") {
        return memory_access_base_register(instruction_tail).is_some_and(|base| base != reg);
    }
    if terminal.contains("pointer arithmetic") {
        return register_operands(instruction_tail).first().copied() != Some(reg);
    }
    false
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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

fn stale_pointer_after_invalidating_helper(context: &ProofSignalContext<'_>) -> bool {
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some((state, state_log_line)) = latest_reg_state_before_instruction_with_log_line(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    ) else {
        return false;
    };
    let Some(pointer_kind) = stale_data_pointer_kind(&context, state, state_log_line, reg) else {
        return false;
    };
    invalidating_helper_between(&context, state_log_line, instruction.line, pointer_kind)
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

fn invalidating_helper_between(
    context: &ProofSignalContext<'_>,
    after_line: usize,
    before_line: usize,
    pointer_kind: StaleDataPointerKind,
) -> bool {
    if after_line >= before_line {
        return false;
    }
    context
        .log
        .lines()
        .enumerate()
        .filter(|(idx, _)| {
            let line = idx + 1;
            line > after_line && line < before_line
        })
        .filter_map(|(idx, line)| {
            let (pc, tail) = parse_instruction_line(line.trim())?;
            let target = call_target_from_instruction_tail(tail)?;
            Some((
                TerminalInstruction {
                    pc,
                    line: idx + 1,
                    tail,
                },
                target,
            ))
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
    let lines = context.log.lines().collect::<Vec<_>>();
    let end = before_line.min(lines.len());
    let start = fragment_start.saturating_sub(1).min(end);
    for (idx, line) in lines[start..end].iter().enumerate().rev() {
        let line_number = start + idx + 1;
        let Some((pc, tail)) = parse_instruction_line(line.trim()) else {
            continue;
        };
        if let Some(source_reg) = register_copy_source(tail, current_reg) {
            current_reg = source_reg;
            continue;
        }
        let target = call_target_from_instruction_tail(tail);
        if current_reg != 0 {
            continue;
        }
        let Some(target) = target else {
            continue;
        };
        let Some(arg_reg) = dynptr_data_producer_arg(target) else {
            return None;
        };
        let instruction = TerminalInstruction {
            pc,
            line: line_number,
            tail,
        };
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

fn register_copy_source(instruction_tail: &str, dest: u8) -> Option<u8> {
    let (_, rest) = instruction_tail.split_once(')')?;
    let rest = rest.trim_start();
    if !(rest.starts_with(&format!("r{dest} = ")) || rest.starts_with(&format!("w{dest} = "))) {
        return None;
    }
    let rhs = rest.split_once(" = ")?.1.split(';').next()?.trim();
    if !rhs.starts_with('r') && !rhs.starts_with('w') {
        return None;
    }
    let regs = register_operands(rhs);
    (regs.len() == 1).then_some(regs[0])
}

fn dynptr_slot_backing_before(
    context: &ProofSignalContext<'_>,
    slot: DynptrStackSlot,
    before_line: usize,
) -> Option<DynptrBacking> {
    let fragment_start = verifier_fragment_start_line(context.log, before_line);
    context
        .log
        .lines()
        .enumerate()
        .filter(|(idx, _)| {
            let line = idx + 1;
            line >= fragment_start && line < before_line
        })
        .filter_map(|(idx, line)| {
            let (pc, tail) = parse_instruction_line(line.trim())?;
            let target = call_target_from_instruction_tail(tail)?;
            let backing = dynptr_backing_from_helper(target)?;
            let arg_reg = dynptr_initializer_output_arg(target)?;
            let instruction = TerminalInstruction {
                pc,
                line: idx + 1,
                tail,
            };
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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
    for line in log
        .lines()
        .skip(fragment_start.saturating_sub(1))
        .take(instruction_line.saturating_sub(fragment_start))
    {
        let Some((_, tail)) = parse_instruction_line(line.trim()) else {
            continue;
        };
        let Some(target) = call_target_from_instruction_tail(tail) else {
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

fn instruction_site_before_line(
    log: &str,
    pc: usize,
    fragment_start: usize,
    before_line: usize,
) -> Option<TerminalInstruction<'_>> {
    log.lines()
        .enumerate()
        .skip(fragment_start.saturating_sub(1))
        .take(before_line.saturating_sub(fragment_start))
        .filter_map(|(idx, line)| {
            let line_number = idx + 1;
            let (line_pc, tail) = parse_instruction_line(line.trim())?;
            (line_pc == pc).then_some(TerminalInstruction {
                pc: line_pc,
                line: line_number,
                tail,
            })
        })
        .last()
}

fn kfunc_argument_type_mismatch(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !kfunc_argument_type_terminal(&terminal) {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    if !kfunc_object_contract_target(target, &terminal) {
        return false;
    }
    let Some(reg) = context
        .register
        .or_else(|| parse_subprogram_arg_register(context.terminal_error))
    else {
        return false;
    };
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some(state) = latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        reg,
    ) else {
        return false;
    };
    if terminal.contains("must be a rcu pointer") {
        if state.reg_type.starts_with("untrusted_ptr") {
            return false;
        }
        return !state.reg_type.starts_with("rcu_ptr")
            && !state.reg_type.starts_with("trusted_ptr");
    }
    if terminal.contains("pointer type struct") && terminal.contains("must point to scalar") {
        return state.reg_type == "fp";
    }
    if let Some(expected) = expected_kfunc_struct_type(&terminal) {
        return !state.reg_type.contains(expected);
    }
    false
}

fn kfunc_argument_type_terminal(terminal: &str) -> bool {
    terminal.contains("must be a rcu pointer")
        || (terminal.contains("pointer type struct") && terminal.contains("must point to scalar"))
        || (terminal.contains("kernel function")
            && terminal.contains("expected pointer to struct")
            && terminal.contains(" but r"))
}

fn kfunc_object_contract_target(target: &str, terminal: &str) -> bool {
    terminal.contains("kernel function")
        || target.contains("cgroup")
        || target.contains("cpumask")
        || target.contains("rbtree")
        || target.contains("kptr")
}

fn parse_subprogram_arg_register(terminal_error: &str) -> Option<u8> {
    let arg = parse_u32_after(terminal_error, "arg#")?;
    if arg >= 5 {
        return None;
    }
    u8::try_from(arg + 1).ok()
}

fn expected_kfunc_struct_type(terminal: &str) -> Option<&str> {
    let (_, after) = terminal.split_once("expected pointer to struct ")?;
    after
        .split(|ch: char| ch.is_ascii_whitespace() || ch == ',' || ch == ';')
        .next()
        .filter(|name| !name.is_empty())
}

fn verifier_type_contract_mismatch(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::TypeContract {
        return false;
    }
    let Some((reg, actual_type)) = terminal_type_contract(context.terminal_error) else {
        return false;
    };
    if !(1..=5).contains(&reg) {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    if direct_call_target_from_instruction_tail(instruction.tail).is_none() {
        return false;
    }
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    latest_type_contract_argument_state(context, instruction, fragment_start, reg)
        .is_some_and(|state| actual_type_matches_state(&actual_type, state))
}

fn latest_type_contract_argument_state<'a>(
    context: &ProofSignalContext<'a>,
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<&'a RegState> {
    let call_frame =
        latest_verifier_state_before_instruction(context.states, instruction, fragment_start_line)
            .map(|state| state.frame);
    let (state, state_log_line) = latest_reg_state_before_instruction_with_log_line(
        context.states,
        instruction,
        fragment_start_line,
        reg,
    )
    .or_else(|| {
        context
            .states
            .iter()
            .filter(|state| state.log_line >= fragment_start_line)
            .filter(|state| {
                context
                    .terminal_line
                    .is_none_or(|line| state.log_line < line)
            })
            .filter(|state| state.pc <= instruction.pc)
            .filter(|state| call_frame.is_none_or(|frame| state.frame == frame))
            .rev()
            .find_map(|state| {
                let reg_state = state.regs.get(&reg)?;
                Some((reg_state, state.log_line))
            })
    })?;
    (!register_written_between(context.log, state_log_line, instruction.line, reg)).then_some(state)
}

fn register_written_between(log: &str, after_line: usize, before_line: usize, reg: u8) -> bool {
    log.lines()
        .enumerate()
        .filter(|(idx, _)| {
            let line = idx + 1;
            line > after_line && line < before_line
        })
        .filter_map(|(_, line)| parse_instruction_line(line.trim()))
        .any(|(_, tail)| instruction_writes_register(tail, reg))
}

fn instruction_writes_register(tail: &str, reg: u8) -> bool {
    let mut tokens = tail.split_whitespace();
    let Some(first) = tokens.next() else {
        return false;
    };
    let Some(destination) = (if first.starts_with('(') {
        tokens.next()
    } else {
        Some(first)
    }) else {
        return false;
    };
    if destination == "call" {
        return reg <= 5;
    }
    if register_write_token(destination) != Some(reg) {
        return false;
    }
    tokens
        .next()
        .is_some_and(|operator| operator.ends_with('='))
}

fn register_write_token(token: &str) -> Option<u8> {
    let token = token.trim_end_matches(|ch| matches!(ch, ',' | ';'));
    let digits = token
        .strip_prefix('r')
        .or_else(|| token.strip_prefix('w'))?;
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

fn terminal_type_contract(message: &str) -> Option<(u8, String)> {
    let reg = register_from_terminal_error(message)?;
    let lower = message.to_ascii_lowercase();
    if lower.contains("trusted arg") {
        return None;
    }
    let (_, after_type) = lower.split_once("type=")?;
    let (actual, after_expected) = after_type.split_once(" expected=")?;
    let actual = actual.trim().trim_end_matches(',');
    let expected = after_expected
        .split(|ch| ch == '\n' || ch == ';')
        .next()
        .unwrap_or("")
        .trim();
    if actual.is_empty() || expected.is_empty() || actual.contains("_or_null") {
        return None;
    }
    if actual == "scalar" && expected_type_list_contains(expected, "map_ptr") {
        return None;
    }
    Some((reg, actual.to_string()))
}

fn expected_type_list_contains(expected: &str, needle: &str) -> bool {
    expected
        .split(',')
        .map(str::trim)
        .any(|item| item == needle)
}

fn actual_type_matches_state(actual_type: &str, state: &RegState) -> bool {
    let state_type = state.reg_type.as_str();
    if state_type == actual_type {
        return true;
    }
    match actual_type {
        "scalar" => state_type == "scalar",
        "fp" => state_type == "fp",
        "ctx" => state_type == "ctx",
        "map_ptr" => state_type == "map_ptr",
        "map_value" => state_type == "map_value",
        "mem" => state_type == "mem",
        "ringbuf_mem" => state_type == "ringbuf_mem",
        "ptr_" => state_type.starts_with("ptr_"),
        "trusted_ptr_" => state_type.starts_with("trusted_ptr"),
        "rcu_ptr_" => state_type.starts_with("rcu_ptr"),
        "untrusted_ptr_" => state_type.starts_with("untrusted_ptr"),
        _ if actual_type.ends_with('_') => state_type.starts_with(actual_type),
        _ => false,
    }
}

fn trusted_nullable_argument(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(target) = call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let fallback_reg = (context.obligation == ProofObligation::Unknown)
        .then(|| nullable_argument_register_from_call_target(target))
        .flatten();
    let Some(reg) = nullable_argument_register(&terminal).or(fallback_reg) else {
        return false;
    };
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let Some(state) = latest_reg_state_for_call_argument(
        context.states,
        instruction,
        fragment_start,
        context.terminal_line,
        reg,
    ) else {
        return false;
    };
    is_trusted_nullable_state(state)
        && (terminal.contains("trusted arg")
            || state.reg_type.starts_with("rcu_ptr_or_null")
            || target == "bpf_kptr_xchg")
}

fn nullable_argument_register(message: &str) -> Option<u8> {
    // The verifier prints trusted kfunc args as zero-based argN, while helper
    // args are one-based and map directly to R1..R5.
    if let Some(arg) = parse_u32_after(message, "trusted arg") {
        return arg.checked_add(1).and_then(|reg| reg.try_into().ok());
    }
    parse_u32_after(message, "helper arg").and_then(|reg| reg.try_into().ok())
}

fn nullable_argument_register_from_call_target(target: &str) -> Option<u8> {
    match target {
        "bpf_kptr_xchg" => Some(2),
        _ => None,
    }
}

fn is_trusted_nullable_state(state: &RegState) -> bool {
    state.reg_type.starts_with("rcu_ptr_or_null") || state.reg_type.starts_with("ptr_or_null")
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
    let base =
        latest_reg_state_before_instruction(context.states, instruction, fragment_start, base_reg)?;
    if base.reg_type != "fp" {
        return None;
    }
    let base_offset = i64::from(base.offset.unwrap_or(0));
    let start = base_offset.checked_add(insn_offset)?;
    let end = start.checked_add(i64::from(width))?;
    Some(StackByteRange {
        start: i16::try_from(start).ok()?,
        end: i16::try_from(end).ok()?,
    })
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
        StackByteRange {
            start: i16::try_from(start).ok()?,
            end: i16::try_from(end).ok()?,
        },
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

fn latest_stack_value_overlap(
    context: &ProofSignalContext<'_>,
    access: StackByteRange,
    target_size: i16,
    target_value: impl Fn(&RegState) -> bool,
) -> Option<bool> {
    latest_stack_slot_overlap(context, access, target_size, |stack| {
        stack
            .value
            .as_ref()
            .is_some_and(|value| target_value(value))
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
            if range.contains(access.start) {
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
            let is_live_ref_dynptr = dynptr_stack_slot_has_live_ref(stack, state);
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

    fn len(self) -> i16 {
        self.end.saturating_sub(self.start)
    }
}

fn stack_value_range(offset: i16, size: i16) -> Option<StackByteRange> {
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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
            let (line_pc, tail) = parse_instruction_line(line.trim())?;
            (line_pc == pc).then_some(TerminalInstruction {
                pc: line_pc,
                line: line_number,
                tail,
            })
        })
        .last()
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

fn terminal_call_target(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<&str> {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .and_then(|instruction| call_target_from_instruction_tail(instruction.tail))
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
        || (parse_instruction_line(line).is_none() && is_verifier_error_line(line))
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

fn memory_access_is_load(line_after_pc: &str) -> bool {
    line_after_pc.contains("= *(")
}

fn memory_access_is_store(line_after_pc: &str) -> bool {
    !memory_access_is_load(line_after_pc)
        && line_after_pc.contains("*)(")
        && line_after_pc.contains(" = ")
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

fn parse_i64_after(message: &str, needle: &str) -> Option<i64> {
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
        if end < bytes.len() && bytes[end] == b'-' {
            end += 1;
        }
        let digit_start = end;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > digit_start {
            return message[start..end].parse().ok();
        }
        search_start = field_start + needle.len();
    }
    None
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
    latest_reg_state_before_instruction_with_frame(states, instruction, fragment_start_line, reg)
        .map(|(state, _)| state)
}

fn latest_reg_state_at_or_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<&'a RegState> {
    let call_frame =
        latest_verifier_state_at_or_before_instruction(states, instruction, fragment_start_line)
            .map(|state| state.frame);
    states
        .iter()
        .filter(|state| state.log_line >= fragment_start_line)
        .filter(|state| state.log_line <= instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .filter(|state| call_frame.is_none_or(|frame| state.frame == frame))
        .rev()
        .find_map(|state| state.regs.get(&reg))
}

fn latest_reg_state_before_instruction_with_log_line<'a>(
    states: &'a [VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<(&'a RegState, usize)> {
    let call_frame =
        latest_verifier_state_before_instruction(states, instruction, fragment_start_line)
            .map(|state| state.frame);
    states
        .iter()
        .filter(|state| state.log_line >= fragment_start_line)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .filter(|state| call_frame.is_none_or(|frame| state.frame == frame))
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            Some((reg_state, state.log_line))
        })
}

fn latest_reg_state_before_instruction_with_frame<'a>(
    states: &'a [VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<(&'a RegState, usize)> {
    let call_frame =
        latest_verifier_state_before_instruction(states, instruction, fragment_start_line)
            .map(|state| state.frame);
    states
        .iter()
        .filter(|state| state.log_line >= fragment_start_line)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .filter(|state| call_frame.is_none_or(|frame| state.frame == frame))
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            Some((reg_state, reg_state.source_frame.unwrap_or(state.frame)))
        })
}

fn latest_verifier_state_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
) -> Option<&'a VerifierInsn> {
    states
        .iter()
        .filter(|state| state.log_line >= fragment_start_line)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .next_back()
}

fn latest_verifier_state_at_or_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
) -> Option<&'a VerifierInsn> {
    states
        .iter()
        .filter(|state| state.log_line >= fragment_start_line)
        .filter(|state| state.log_line <= instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .next_back()
}

fn latest_ref_state_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start_line: usize,
) -> Option<&'a VerifierInsn> {
    states
        .iter()
        .filter(|state| state.log_line >= fragment_start_line)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .filter(|state| !state.ref_ids.is_empty())
        .next_back()
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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

fn direct_call_target_from_instruction_tail(instruction_tail: &str) -> Option<&str> {
    let mut tokens = instruction_tail.split_whitespace();
    if tokens.next()? != "(85)" || tokens.next()? != "call" {
        return None;
    }
    let call = tokens.next()?;
    call.split_once('#')
        .map(|(target, _)| target)
        .or(Some(call))
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
        .filter_map(parse_instruction_line)
        .filter(|(pc, _)| *pc >= guard_pc && *pc <= max_pc)
        .filter_map(|(pc, tail)| {
            let regs = conditional_branch_registers(tail);
            (!regs.is_empty()).then_some((pc, regs))
        })
        .collect()
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
            let Some((pc, tail)) = parse_instruction_line(line.trim()) else {
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
        .filter_map(|(_, line)| parse_instruction_line(line.trim()))
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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

fn scalar_state_upper_bound_at_most(state: &RegState, relation_capacity: u32) -> bool {
    if state.reg_type != "scalar" {
        return false;
    }
    let capacity = u64::from(relation_capacity);
    state.exact_value.is_some_and(|value| value <= capacity)
        || state.range.umax.is_some_and(|value| value <= capacity)
        || state
            .range
            .smax
            .is_some_and(|value| value >= 0 && value as u64 <= capacity)
        || state
            .range
            .umax32
            .is_some_and(|value| value <= relation_capacity)
        || state
            .range
            .smax32
            .is_some_and(|value| value >= 0 && value as u32 <= relation_capacity)
}

fn map_value_remaining_capacity(state: &RegState, value_size: u32) -> Option<u32> {
    let fixed_offset = state.offset.unwrap_or(0);
    let fixed_offset = u32::try_from(fixed_offset).ok()?;
    value_size.checked_sub(fixed_offset)
}

fn map_value_access_range_may_exceed_value_size(state: &RegState, access_size: u32) -> bool {
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
        (None, None) => Some(0),
    };
    max_offset
        .and_then(|offset| offset.checked_add(u64::from(access_size)))
        .is_some_and(|end| end > u64::from(value_size))
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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

fn scalar_range_min_i64(state: &RegState) -> Option<i64> {
    state
        .range
        .smin
        .or_else(|| state.range.umin.and_then(|value| i64::try_from(value).ok()))
        .or_else(|| state.range.smin32.map(i64::from))
        .or_else(|| state.range.umin32.map(i64::from))
}

fn scalar_range_max_i64(state: &RegState) -> Option<i64> {
    state
        .range
        .smax
        .or_else(|| state.range.umax.and_then(|value| i64::try_from(value).ok()))
        .or_else(|| state.range.smax32.map(i64::from))
        .or_else(|| state.range.umax32.map(i64::from))
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
    let fragment_start = context
        .terminal_line
        .map(|line| verifier_fragment_start_line(context.log, line))
        .unwrap_or_else(|| verifier_fragment_start_line(context.log, instruction.line));
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

fn instruction_reads_register(opcode_tail: &str, reg: u8) -> bool {
    if let Some(operand) = memory_access_operand(opcode_tail) {
        return register_operands(operand).contains(&reg);
    }
    if opcode_tail.split_once(" = ").is_some() {
        return false;
    }
    register_operands(opcode_tail).contains(&reg)
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

fn scalar_range_may_include_zero(state: &RegState) -> bool {
    if let Some(value) = state.exact_value {
        return value == 0;
    }
    if state.range.smax.is_some_and(|value| value < 0) {
        return false;
    }
    if state.range.smin.is_some_and(|value| value > 0) {
        return false;
    }
    if state.range.umin.is_some_and(|value| value > 0) {
        return false;
    }
    true
}

fn scalar_range_may_be_negative(state: &RegState) -> bool {
    if let Some(value) = state.exact_value {
        return value > i64::MAX as u64;
    }
    if let Some(smin) = state.range.smin {
        return smin < 0;
    }
    state.range.umin.is_none()
}

fn scalar_range_upper_unbounded_or_too_large(state: &RegState) -> bool {
    let signed_too_large = state
        .range
        .smax
        .is_some_and(|value| value > i32::MAX as i64);
    let unsigned_too_large = state
        .range
        .umax
        .is_some_and(|value| value > i32::MAX as u64);
    let unbounded = state.range.smax.is_none() && state.range.umax.is_none();
    signed_too_large || unsigned_too_large || unbounded
}

fn scalar_range_has_any_bound(state: &RegState) -> bool {
    state.range.smin.is_some()
        || state.range.smax.is_some()
        || state.range.umin.is_some()
        || state.range.umax.is_some()
        || state.range.smin32.is_some()
        || state.range.smax32.is_some()
        || state.range.umin32.is_some()
        || state.range.umax32.is_some()
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
    use super::{analyze_verifier_log, ProofEventEvidence, ProofEventRole, ProofSignal};
    use crate::family::ProofObligation;

    #[test]
    fn unsupported_terminal_replacement_is_an_explicit_signal_whitelist() {
        let replaceable = [
            ProofSignal::BtfFuncInfoMissing,
            ProofSignal::ContextAccessSourceArgumentMismatch,
            ProofSignal::DynptrStackStorageAccess,
            ProofSignal::DynptrSliceVariableLength,
            ProofSignal::ExceptionThrowWithLiveReference,
            ProofSignal::ReferenceLiveAtExit,
            ProofSignal::IrqFlagStateMismatch,
            ProofSignal::IrqRestoreOrderMismatch,
            ProofSignal::IrqRestoreHelperClassMismatch,
            ProofSignal::IrqStateLiveAtExit,
            ProofSignal::IteratorHelperArgumentStateMismatch,
            ProofSignal::IteratorStackStorageAccess,
            ProofSignal::MapLookupKeyArgumentUnreadable,
            ProofSignal::MapPointerArgumentScalarZero,
            ProofSignal::MapValueGuardExceedsValueSize,
            ProofSignal::MapValueRelationPrecisionBoundary,
            ProofSignal::PacketGuardUndercoversAccess,
            ProofSignal::PacketMaxOffsetPrecisionBoundary,
            ProofSignal::SubprogramReferenceMetadataMissing,
            ProofSignal::TrustedNullableArgument,
        ];
        for signal in replaceable {
            assert!(
                signal.can_replace_unsupported_terminal(),
                "{signal:?} should replace unsupported terminal messages"
            );
        }

        let lowering_only = [
            ProofSignal::WideStackAlignment,
            ProofSignal::SharedInstructionPointerMerge,
            ProofSignal::SharedInstructionPathProofLoss,
            ProofSignal::Alu32PointerCopyDropsProvenance,
            ProofSignal::ConstantScalarMemoryLoad,
            ProofSignal::SharedInstructionUninitializedRegister,
            ProofSignal::PointerShiftDropsProvenance,
            ProofSignal::ModifiedContextPointer,
            ProofSignal::SubprogramContextArgumentDropped,
            ProofSignal::PacketPointerProofLostAfterBoundsCheck,
            ProofSignal::PacketRangeProofLostBeforeAccess,
            ProofSignal::MapValueWideAccess,
            ProofSignal::MapValueCheckedOffsetRelationLost,
        ];
        for signal in lowering_only {
            assert!(
                !signal.can_replace_unsupported_terminal(),
                "{signal:?} should not replace unsupported terminal messages"
            );
        }
    }

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

        let derived_header_log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-76277872/replay-verifier.log");
        let analysis = analyze_verifier_log(
            derived_header_log,
            Some(6),
            None,
            "invalid access to packet, off=26 size=4, R1(id=0,off=26,r=14); R1 offset is outside of the packet",
            None,
            ProofObligation::PacketBounds,
        )
        .unwrap();
        assert!(
            analysis
                .signals
                .contains(&ProofSignal::PacketAccessWithoutBoundsProof),
            "signals: {:?}",
            analysis.signals
        );
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
        assert!(analysis
            .signals
            .contains(&ProofSignal::UnreadableReturnRegister));
    }

    #[test]
    fn unreadable_program_entry_argument_is_a_source_state_signal() {
        let log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-69506785/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(0),
            None,
            "R2 !read_ok",
            None,
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(analysis
            .signals
            .contains(&ProofSignal::UnreadableProgramEntryArgument));
    }

    #[test]
    fn unreadable_helper_argument_is_a_source_state_signal() {
        let log = include_str!(
            "../../../bpfix-bench/cases/github-commit-cilium-6b3c9f16c99f/replay-verifier.log"
        );
        let analysis = analyze_verifier_log(
            log,
            Some(6),
            None,
            "R5 !read_ok",
            Some("bpf_skb_store_bytes"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(analysis
            .signals
            .contains(&ProofSignal::UnreadableHelperArgument));
    }

    #[test]
    fn scalar_pointer_dereference_is_a_source_state_signal() {
        let log = include_str!(
            "../../../bpfix-bench/cases/github-commit-bcc-02daf8d84ecd/replay-verifier.log"
        );
        let analysis = analyze_verifier_log(
            log,
            Some(1),
            None,
            "R1 invalid mem access 'scalar'",
            None,
            ProofObligation::PointerProvenance,
        )
        .unwrap();

        assert!(analysis
            .signals
            .contains(&ProofSignal::ScalarValueUsedAsPointer));
    }

    #[test]
    fn stale_packet_pointer_after_helper_is_a_source_state_signal() {
        let log = include_str!(
            "../../../bpfix-bench/cases/github-commit-cilium-2ff1a462cd33/replay-verifier.log"
        );
        let analysis = analyze_verifier_log(
            log,
            Some(10),
            None,
            "R7 invalid mem access 'scalar'",
            None,
            ProofObligation::PointerProvenance,
        )
        .unwrap();

        assert!(analysis
            .signals
            .contains(&ProofSignal::StalePointerAfterInvalidatingHelper));
    }

    #[test]
    fn stale_dynptr_data_after_reinit_helper_is_a_source_state_signal() {
        let log = include_str!(
            "../../../bpfix-bench/cases/kernel-selftest-dynptr-fail-dynptr-invalidate-slice-reinit-raw-tp-f5b71f50/replay-verifier.log"
        );
        let analysis = analyze_verifier_log(
            log,
            Some(52),
            None,
            "R7 invalid mem access 'scalar'",
            None,
            ProofObligation::PointerProvenance,
        )
        .unwrap();

        assert!(analysis
            .signals
            .contains(&ProofSignal::StalePointerAfterInvalidatingHelper));
    }

    #[test]
    fn prohibited_pointer_arithmetic_is_a_source_state_signal() {
        let log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-68460177/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(37),
            None,
            "R4 bitwise operator |= on pointer prohibited",
            None,
            ProofObligation::PointerProvenance,
        )
        .unwrap();

        assert!(analysis
            .signals
            .contains(&ProofSignal::ProhibitedPointerArithmetic));
    }

    #[test]
    fn map_lookup_unreadable_key_stays_stack_initialization_signal() {
        let log = "\
; value = bpf_map_lookup_elem(&map, key); @ prog.c:20
4: (85) call bpf_map_lookup_elem#1
R2 !read_ok
";
        let analysis = analyze_verifier_log(
            log,
            Some(4),
            None,
            "R2 !read_ok",
            Some("bpf_map_lookup_elem"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(analysis
            .signals
            .contains(&ProofSignal::MapLookupKeyArgumentUnreadable));
        assert!(!analysis
            .signals
            .contains(&ProofSignal::UnreadableProgramEntryArgument));
        assert!(!analysis
            .signals
            .contains(&ProofSignal::UnreadableHelperArgument));
    }

    #[test]
    fn ordinary_helper_unreadable_arg_stays_stack_initialization_without_signal() {
        let log = "\
0: R1=ctx() R10=fp0
; bpf_probe_read_kernel(dst, len, key); @ prog.c:19
2: (85) call bpf_probe_read_kernel#113
R2 !read_ok
";
        let analysis = analyze_verifier_log(
            log,
            Some(2),
            None,
            "R2 !read_ok",
            Some("bpf_probe_read_kernel"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(!analysis
            .signals
            .contains(&ProofSignal::UnreadableProgramEntryArgument));
        assert!(!analysis
            .signals
            .contains(&ProofSignal::UnreadableHelperArgument));
    }

    #[test]
    fn legacy_skb_access_is_not_program_entry_abi_signal() {
        let log = "\
0: R1=ctx() R10=fp0
; asm volatile (\"r0 = *(u8 *)skb[9]\" ::: \"r0\"); @ prog.c:8
0: (30) r0 = *(u8 *)skb[9]
R6 !read_ok
";
        let analysis = analyze_verifier_log(
            log,
            Some(0),
            None,
            "R6 !read_ok",
            None,
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(!analysis
            .signals
            .contains(&ProofSignal::UnreadableProgramEntryArgument));
        assert!(!analysis
            .signals
            .contains(&ProofSignal::UnreadableHelperArgument));
        assert!(analysis
            .signals
            .contains(&ProofSignal::LegacySkbLoadUnreadableRegister));

        let readable_r6_log = "\
0: R1=ctx() R6=ctx() R10=fp0
; asm volatile (\"r0 = *(u8 *)skb[9]\" ::: \"r0\"); @ prog.c:8
0: (30) r0 = *(u8 *)skb[9]
R6 !read_ok
";
        let analysis = analyze_verifier_log(
            readable_r6_log,
            Some(0),
            None,
            "R6 !read_ok",
            None,
            ProofObligation::StackInitialized,
        )
        .unwrap();
        assert!(!analysis
            .signals
            .contains(&ProofSignal::LegacySkbLoadUnreadableRegister));

        let stale_r6_from_earlier_full_state = "\
0: R1=ctx() R6=ctx() R10=fp0
0: R1=ctx() R10=fp0
; asm volatile (\"r0 = *(u8 *)skb[9]\" ::: \"r0\"); @ prog.c:8
0: (30) r0 = *(u8 *)skb[9]
R6 !read_ok
";
        let analysis = analyze_verifier_log(
            stale_r6_from_earlier_full_state,
            Some(0),
            None,
            "R6 !read_ok",
            None,
            ProofObligation::StackInitialized,
        )
        .unwrap();
        assert!(analysis
            .signals
            .contains(&ProofSignal::LegacySkbLoadUnreadableRegister));

        let no_snapshot_log = "\
; asm volatile (\"r0 = *(u8 *)skb[9]\" ::: \"r0\"); @ prog.c:8
0: (30) r0 = *(u8 *)skb[9]
R6 !read_ok
";
        let analysis = analyze_verifier_log(
            no_snapshot_log,
            Some(0),
            None,
            "R6 !read_ok",
            None,
            ProofObligation::StackInitialized,
        )
        .unwrap();
        assert!(!analysis
            .signals
            .contains(&ProofSignal::LegacySkbLoadUnreadableRegister));
    }

    #[test]
    fn helper_stack_read_length_exceeding_initialized_bytes_is_source_state_signal() {
        let helper_stack_read_signal = |log: &str, terminal_error: &str| {
            analyze_verifier_log(
                log,
                Some(2),
                None,
                terminal_error,
                Some("bpf_dynptr_slice"),
                ProofObligation::StackInitialized,
            )
            .unwrap()
            .signals
            .contains(&ProofSignal::HelperStackReadExceedsInitializedRange)
        };
        let log = "\
0: R1=ctx() R10=fp0
1: (7b) *(u64 *)(r10 -24) = r2        ; R2_w=0 R10=fp0 fp-24_w=0
2: (bf) r3 = r10                      ; R3_w=fp0 R10=fp0
3: (07) r3 += -24                     ; R3_w=fp-24
4: (b7) r4 = 9                        ; R4_w=9
5: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        let analysis = analyze_verifier_log(
            log,
            Some(5),
            None,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(analysis
            .signals
            .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

        let branch_paths_are_not_mixed = "\
0: R1=ctx() R10=fp0
1: R3=fp-32 R4=16 R10=fp0 fp-32_w=0
from 1 to 2: R3=fp-32 R4=16 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -32+8 size 16
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        assert!(helper_stack_read_signal(
            branch_paths_are_not_mixed,
            "invalid read from stack R3 off -32+8 size 16; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

        let pc_full_states_are_not_merged = "\
0: R1=ctx() R10=fp0 fp-32_w=0
1: R3=fp-32 R4=16 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -32+8 size 16
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        assert!(helper_stack_read_signal(
            pc_full_states_are_not_merged,
            "invalid read from stack R3 off -32+8 size 16; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

        let branch_delta_state_is_part_of_current_path = "\
0: R1=ctx() R10=fp0 fp-24_w=0
1: (55) if r1 != 0x0 goto pc+1      ; R3=fp-24 R4=9 R10=fp0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        assert!(helper_stack_read_signal(
            branch_delta_state_is_part_of_current_path,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

        let partial_low_half_read = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=4 R10=fp0 fp-24=0000????
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+0 size 4
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        let analysis = analyze_verifier_log(
            partial_low_half_read,
            Some(2),
            None,
            "invalid read from stack R3 off -24+0 size 4; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
        assert!(analysis
            .signals
            .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

        let partial_high_half_read = "\
0: R1=ctx() R10=fp0
1: R3=fp-20 R4=4 R10=fp0 fp-24=0000????
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -20+0 size 4
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        let analysis = analyze_verifier_log(
            partial_high_half_read,
            Some(2),
            None,
            "invalid read from stack R3 off -20+0 size 4; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
        assert!(!analysis
            .signals
            .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

        let oversized_exact_length = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=65535 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+0 size 65535
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        let analysis = analyze_verifier_log(
            oversized_exact_length,
            Some(2),
            None,
            "invalid read from stack R3 off -24+0 size 65535; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
        assert!(analysis
            .signals
            .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

        let iterator_slot_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16_w=iter_num()
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+0 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        let analysis = analyze_verifier_log(
            iterator_slot_is_not_plain_buffer,
            Some(2),
            None,
            "invalid read from stack R3 off -24+0 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
        assert!(analysis
            .signals
            .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

        let frame_pointer_spill_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16=fp-40
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        assert!(helper_stack_read_signal(
            frame_pointer_spill_is_not_plain_buffer,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

        let map_value_spill_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16=map_value(map=demo,ks=4,vs=8)
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        assert!(helper_stack_read_signal(
            map_value_spill_is_not_plain_buffer,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

        let ctx_spill_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16=ctx()
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        assert!(helper_stack_read_signal(
            ctx_spill_is_not_plain_buffer,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

        let raw_dynptr_slot_type_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16=dddddddd
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+0 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        let analysis = analyze_verifier_log(
            raw_dynptr_slot_type_is_not_plain_buffer,
            Some(2),
            None,
            "invalid read from stack R3 off -24+0 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
        assert!(analysis
            .signals
            .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

        let adjacent_initialized_slots = "\
0: R1=ctx() R10=fp0
1: R3=fp-32 R4=16 R10=fp0 fp-32_w=0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -32+0 size 16
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        let analysis = analyze_verifier_log(
            adjacent_initialized_slots,
            Some(2),
            None,
            "invalid read from stack R3 off -32+0 size 16; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
        assert!(!analysis
            .signals
            .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

        let reported_register_mismatch = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R2 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        assert!(!helper_stack_read_signal(
            reported_register_mismatch,
            "invalid read from stack R2 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

        let reported_offset_mismatch = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -16+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        assert!(!helper_stack_read_signal(
            reported_offset_mismatch,
            "invalid read from stack R3 off -16+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

        let reported_size_mismatch = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=70000 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 65535
arg#2 arg#3 memory, len pair leads to invalid memory access
";
        assert!(!helper_stack_read_signal(
            reported_size_mismatch,
            "invalid read from stack R3 off -24+8 size 65535; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));
    }

    #[test]
    fn static_helper_signature_is_not_program_entry_abi_signal() {
        let log = "\
0: R1=ctx() R10=fp0
; static int helper(void *ctx, int arg) @ prog.c:8
0: (bf) r3 = r2
R2 !read_ok
";
        let analysis = analyze_verifier_log(
            log,
            Some(0),
            None,
            "R2 !read_ok",
            None,
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(!analysis
            .signals
            .contains(&ProofSignal::UnreadableProgramEntryArgument));
        assert!(!analysis
            .signals
            .contains(&ProofSignal::UnreadableHelperArgument));
    }

    #[test]
    fn helper_stack_write_beyond_frame_is_a_source_state_signal() {
        let log = include_str!(
            "../../../bpfix-bench/cases/github-commit-cilium-31a01b994f8b/replay-verifier.log"
        );
        let analysis = analyze_verifier_log(
            log,
            Some(3),
            None,
            "invalid write to stack R1 off=-600 size=600",
            Some("bpf_get_current_comm"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(analysis
            .signals
            .contains(&ProofSignal::HelperStackWriteBeyondFrame));
    }

    #[test]
    fn helper_stack_write_inside_frame_is_not_beyond_frame_signal() {
        let log = "\
0: R1=ctx() R10=fp0
1: R1_w=fp-16 R2_w=16 R10=fp0
1: (85) call bpf_get_current_comm#16
invalid write to stack R1 off=-16 size=16
";
        let analysis = analyze_verifier_log(
            log,
            Some(1),
            None,
            "invalid write to stack R1 off=-16 size=16",
            Some("bpf_get_current_comm"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(!analysis
            .signals
            .contains(&ProofSignal::HelperStackWriteBeyondFrame));
    }

    #[test]
    fn ordinary_stack_store_is_not_helper_stack_write_signal() {
        let log = "\
0: R1=fp-600 R2=scalar(id=1) R10=fp0
0: (7b) *(u64 *)(r1 +0) = r2
invalid write to stack R1 off=-600 size=8
";
        let analysis = analyze_verifier_log(
            log,
            Some(0),
            None,
            "invalid write to stack R1 off=-600 size=8",
            None,
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(!analysis
            .signals
            .contains(&ProofSignal::HelperStackWriteBeyondFrame));
    }

    #[test]
    fn helper_stack_write_requires_modeled_helper_signature() {
        let log = "\
0: R1=ctx() R10=fp0
1: R1_w=fp-600 R2_w=600 R10=fp0
1: (85) call bpf_probe_read_kernel#113
invalid write to stack R1 off=-600 size=600
";
        let analysis = analyze_verifier_log(
            log,
            Some(1),
            None,
            "invalid write to stack R1 off=-600 size=600",
            Some("bpf_probe_read_kernel"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(!analysis
            .signals
            .contains(&ProofSignal::HelperStackWriteBeyondFrame));
    }

    #[test]
    fn helper_stack_write_requires_matching_length_state() {
        let log = "\
0: R1=ctx() R10=fp0
1: R1_w=fp-600 R2_w=16 R10=fp0
1: (85) call bpf_get_current_comm#16
invalid write to stack R1 off=-600 size=600
";
        let analysis = analyze_verifier_log(
            log,
            Some(1),
            None,
            "invalid write to stack R1 off=-600 size=600",
            Some("bpf_get_current_comm"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(!analysis
            .signals
            .contains(&ProofSignal::HelperStackWriteBeyondFrame));
    }

    #[test]
    fn helper_stack_write_requires_matching_frame_pointer_offset() {
        let log = "\
0: R1=ctx() R10=fp0
1: R1_w=fp-608 R2_w=600 R10=fp0
1: (85) call bpf_get_current_comm#16
invalid write to stack R1 off=-600 size=600
";
        let analysis = analyze_verifier_log(
            log,
            Some(1),
            None,
            "invalid write to stack R1 off=-600 size=600",
            Some("bpf_get_current_comm"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

        assert!(!analysis
            .signals
            .contains(&ProofSignal::HelperStackWriteBeyondFrame));
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
        assert!(analysis.signals.contains(&ProofSignal::ReferenceLiveAtExit));

        let released_before_exit = "\
5: (85) call bpf_ringbuf_reserve#131 ; R0_w=ringbuf_mem_or_null(id=2,ref_obj_id=2) refs=2
6: R0=scalar()
7: (95) exit
Unreleased reference id=2 alloc_insn=5
";
        let analysis = analyze_verifier_log(
            released_before_exit,
            Some(7),
            None,
            "Unreleased reference id=2 alloc_insn=5",
            None,
            ProofObligation::ReferenceLifecycle,
        )
        .unwrap();

        assert!(!analysis.signals.contains(&ProofSignal::ReferenceLiveAtExit));
    }
}
