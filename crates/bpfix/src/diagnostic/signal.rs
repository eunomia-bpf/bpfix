use crate::output::NextAction;

macro_rules! proof_signal_variants {
    ($macro:ident) => {
        $macro! {
            WideStackAlignment,
            AtomicMemoryAccessScalarBase,
            LoopBackEdgeStateRepeats,
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
            NullScalarDereferenceAfterPointerProof,
            TrustedNullableArgument,
            KfuncArgumentTypeMismatch,
            VerifierTypeContractMismatch,
            ModernBpfObjectProtocolViolation,
            ContextAccessSourceArgumentMismatch,
            TraceContextScalarArgumentMismatch,
            ContextFieldUnavailable,
            PacketContextFieldAccessInUnsupportedProgram,
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
            HelperStackReadLengthExceedsInitializedRange,
            HelperStackReadExceedsInitializedRange,
            HelperStackWriteBeyondFrame,
            ScalarValueUsedAsPointer,
            OpaqueScalarPointerDereference,
            StalePointerAfterInvalidatingHelper,
            DynptrDataPointerInvalidatedBeforeUse,
            ProhibitedPointerArithmetic,
            PacketGuardUndercoversAccess,
            PacketMaxOffsetPrecisionBoundary,
            MapValueRelationPrecisionBoundary,
        }
    };
}

macro_rules! define_proof_signal_enum {
    ($($variant:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ProofSignal {
            $($variant),+
        }
    };
}

proof_signal_variants!(define_proof_signal_enum);

#[cfg(test)]
macro_rules! define_all_proof_signals {
    ($($variant:ident),+ $(,)?) => {
        pub(super) const ALL_PROOF_SIGNALS: &[ProofSignal] = &[
            $(ProofSignal::$variant),+
        ];
    };
}

#[cfg(test)]
proof_signal_variants!(define_all_proof_signals);

#[derive(Clone, Copy)]
struct SignalInfo {
    signal: ProofSignal,
    failure_class: &'static str,
    summary: &'static str,
    help_safety: &'static str,
    next_action: NextAction,
    evidence_kind: &'static str,
    evidence_detail: &'static str,
    help: &'static str,
    selection_rank: u8,
    can_replace_unsupported_terminal: bool,
    replaces_classifier_help: bool,
    required_proof_override: Option<&'static str>,
    primary_label_override: Option<&'static str>,
    error_id_override: Option<&'static str>,
}

macro_rules! signal_info {
    (
        $signal:ident,
        $failure_class:expr,
        $summary:expr,
        $help_safety:expr,
        $next_action:ident,
        $evidence_kind:expr,
        $evidence_detail:expr,
        $help:expr,
        $selection_rank:expr,
        $can_replace_unsupported_terminal:expr,
        $replaces_classifier_help:expr,
        $required_proof_override:expr,
        $primary_label_override:expr,
        $error_id_override:expr $(,)?
    ) => {
        SignalInfo {
            signal: ProofSignal::$signal,
            failure_class: $failure_class,
            summary: $summary,
            help_safety: $help_safety,
            next_action: NextAction::$next_action,
            evidence_kind: $evidence_kind,
            evidence_detail: $evidence_detail,
            help: $help,
            selection_rank: $selection_rank,
            can_replace_unsupported_terminal: $can_replace_unsupported_terminal,
            replaces_classifier_help: $replaces_classifier_help,
            required_proof_override: $required_proof_override,
            primary_label_override: $primary_label_override,
            error_id_override: $error_id_override,
        }
    };
}

#[rustfmt::skip]
const SIGNAL_INFOS: &[SignalInfo] = &[
    signal_info!(WideStackAlignment, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Provenance, "lowering_artifact_signal", "compiler-lowered stack access requires stronger alignment than the source layout exposes", "wide stack loads, stores, copies, or inline assembly can make stack-object alignment a verifier-visible property; align the stack object or avoid the wide access shape.", 20, false, false, None, None, None),
    signal_info!(AtomicMemoryAccessScalarBase, "source_bug", "atomic memory operation uses a scalar base instead of an aligned pointer", "repair_hint", Provenance, "verifier_state_signal", "verifier state at the rejected atomic memory operation shows the base register is scalar, so the verifier has no pointer alignment proof for the access", "Keep the atomic target as verifier-visible aligned storage, for example by applying the atomic operation to the map-value field itself instead of to a scalar value loaded from that field.", 10, false, true, Some("prove the atomic memory operand is a verifier-visible aligned pointer, not a scalar loaded from another object"), Some("this atomic operation uses a scalar as its memory base"), Some("BPFIX-E007")),
    signal_info!(LoopBackEdgeStateRepeats, "source_bug", "loop back-edge repeats verifier state without a visible terminating bound", "repair_hint", Budget, "verifier_state_signal", "verifier printed matching current and previous loop-entry states at the rejected back edge, so no loop-carried value proves monotonic progress toward a finite bound", "Make loop progress verifier-visible with a constant upper bound and an induction variable updated on every back-edge path; do not rely on data-dependent lookup failure as the only exit.", 10, false, true, Some("prove the back edge can execute only a statically bounded number of times with a verifier-visible induction variable"), Some("current and previous loop-entry states repeat at this back edge"), Some("BPFIX-E018")),
    signal_info!(SharedInstructionPointerMerge, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Provenance, "lowering_artifact_signal", "compiler code merging hides distinct pointer proofs from the verifier", "Keep incompatible pointer-typed paths separated at the dereference, or force the load to stay branch-local so one instruction is not shared by different verifier pointer types.", 20, false, false, None, None, None),
    signal_info!(SharedInstructionPathProofLoss, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Provenance, "lowering_artifact_signal", "one verifier path reaches this shared instruction with a valid pointer proof, but another path reaches it after the proof is clobbered", "Keep the checked pointer use on the path where the pointer proof is established, or split the shared instruction so the clobbered path cannot reach it.", 10, false, false, None, None, None),
    signal_info!(Alu32PointerCopyDropsProvenance, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Provenance, "lowering_artifact_signal", "a 32-bit register copy materializes a packet pointer as a scalar and drops verifier pointer provenance", "Keep packet pointers in 64-bit verifier-tracked registers; avoid 32-bit moves or ALU32 lowering for pointer values before packet access.", 10, false, false, None, None, None),
    signal_info!(ConstantScalarMemoryLoad, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Provenance, "lowering_artifact_signal", "bytecode tries to dereference a small scalar constant, which is a compiler or relocation lowering shape rather than a verifier-tracked pointer", "Rebuild the object with verifier-friendly optimization and relocation settings so field offsets are folded into recognized pointer accesses instead of standalone scalar dereferences.", 10, false, false, None, None, None),
    signal_info!(SharedInstructionUninitializedRegister, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Initialize, "lowering_artifact_signal", "one verifier path initializes this register before a shared instruction, but another path reaches the same instruction without that register proof", "Initialize the register on every path before the shared instruction, or keep the path-specific spill/load separate so the verifier can see the initialized value.", 10, false, false, None, None, None),
    signal_info!(PointerShiftDropsProvenance, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Provenance, "lowering_artifact_signal", "a verifier-tracked pointer reaches a left-shift instruction, which the verifier rejects because the operation destroys pointer provenance", "The rejected pointer-shift line must not remain as-is; delete it or keep scalar-only bit operations separate, then derive the access pointer from a checked packet or context base.", 20, false, false, None, None, None),
    signal_info!(ModifiedContextPointer, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Context, "lowering_artifact_signal", "compiler-lowered context access violates the verifier context contract", "Keep context field accesses as verifier-recognized field loads; avoid wide casts or modified context pointers for adjacent fields.", 20, false, false, None, None, None),
    signal_info!(SubprogramContextArgumentDropped, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Provenance, "lowering_artifact_signal", "compiler liveness hides the context argument required by a BPF subprogram", "Keep the context argument verifier-visible at the BPF-to-BPF callsite, for example by passing it directly or preventing the compiler from dropping the value.", 20, false, false, None, None, None),
    signal_info!(PacketPointerProofLostAfterBoundsCheck, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Provenance, "lowering_artifact_signal", "compiler-lowered control flow hides an established packet-pointer proof", "Keep the checked packet pointer derivation in the same verifier-visible path as the dereference, or rederive it from a checked base immediately before use.", 10, false, false, None, None, None),
    signal_info!(PacketRangeProofLostBeforeAccess, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Bounds, "lowering_artifact_signal", "verifier state proves the packet access range earlier, but the rejected path reaches the access after that range proof is lost", "Keep the packet pointer that received the sufficient data_end range proof live through the access, or recheck the final derived pointer immediately before dereferencing it.", 10, false, false, None, None, None),
    signal_info!(PacketAccessWithoutBoundsProof, "source_bug", "packet access reaches the use before the verifier has enough packet range", "repair_hint", Bounds, "verifier_state_signal", "verifier state shows the packet register's proven range is shorter than the rejected access requires at this instruction", "Move or add a data_end bounds check for the exact packet pointer and access width immediately before the load, store, or helper call that consumes it.", 50, false, true, Some("prove this packet register has range at least off + size at the rejected load, store, or helper call"), Some("packet range proof is too short for this access"), Some("BPFIX-E001")),
    signal_info!(MapValueWideAccess, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Bounds, "lowering_artifact_signal", "bytecode performs a map-value access wider than the verifier-proven map value size", "Keep generated or lowered map-value loads and stores within the declared value type width; avoid widening a 32-bit value access into a 64-bit BPF memory operation.", 10, false, false, None, None, None),
    signal_info!(MapValueCheckedOffsetRelationLost, "lowering_artifact", "verifier-visible compiler lowering hides the required proof", "repair_hint", Provenance, "lowering_artifact_signal", "source bounds the map-value expression to the declared value size, but verifier state later sees the rebuilt pointer range cross that size", "Reuse the exact bounded map-value address expression at the access site, or store the checked remaining capacity in one scalar that the final load uses directly.", 10, false, false, None, None, None),
    signal_info!(MapValueGuardExceedsValueSize, "source_bug", "map-value index guard exceeds the map value size", "repair_hint", Bounds, "verifier_state_signal", "source bounds the map-value index to a range larger than the verifier-visible value size allows", "Clamp the map-value index to the array length or remaining bytes inside the map value; the guard must account for field offset plus access width.", 5, true, false, Some("prove the map-value index plus field offset and access width stays below the map value size"), Some("map value index guard is wider than the value field can hold"), None),
    signal_info!(MapValueAccessOutOfBounds, "source_bug", "map-value access exceeds the verifier-visible value size", "repair_hint", Bounds, "verifier_state_signal", "verifier state shows the rejected map-value pointer access crosses the declared value size", "Keep map-value field offsets, array indexes, and helper lengths inside the declared map value size; resize the map value or clamp the access before the load, store, or helper call.", 6, false, true, Some("prove the map-value field offset plus access width stays below the declared map value size at the rejected access"), Some("this map-value access crosses the declared value size"), Some("BPFIX-E005")),
    signal_info!(MemoryObjectAccessOutOfBounds, "source_bug", "memory-object access exceeds the verifier-visible object size", "repair_hint", Bounds, "verifier_state_signal", "verifier state shows the rejected memory pointer has a fixed object size and the access crosses that object boundary", "Keep dynptr slice or helper-returned memory accesses inside the verifier-reported object size; clamp the offset and width before dereferencing the memory pointer.", 55, false, true, Some("prove the memory pointer offset plus access width stays inside the verifier-reported object size at the rejected access"), Some("this memory access crosses the verifier-reported object size"), Some("BPFIX-E005")),
    signal_info!(ReturnRangeOutOfBounds, "source_bug", "program return value is outside the verifier-required range", "repair_hint", Bounds, "verifier_state_signal", "verifier state reaches BPF_EXIT with a return register value or range outside the terminal return-value contract", "Return only values in the verifier-required range on every exit path; clamp or branch on the computed return value before BPF_EXIT.", 55, false, true, Some("prove the value in R0 is inside the verifier-required return range at every BPF_EXIT"), Some("this exit returns a value outside the verifier-required range"), Some("BPFIX-E005")),
    signal_info!(StackVariableOffsetOutOfBounds, "source_bug", "stack variable-offset access crosses the verifier stack frame", "repair_hint", Bounds, "verifier_state_signal", "verifier state shows the stack pointer's variable byte interval can leave the valid BPF stack frame at the rejected access", "Clamp the stack index so the final frame-pointer byte range stays within -512..0, accounting for the base offset and access width.", 55, false, true, Some("prove the final stack byte interval stays inside the verifier stack frame at the rejected access"), Some("this stack access can leave the verifier stack frame"), Some("BPFIX-E005")),
    signal_info!(ScalarRangeUnsafeAtUse, "source_bug", "scalar range at the rejected use is still verifier-unsafe", "repair_hint", Bounds, "verifier_state_signal", "verifier state shows the rejected scalar or pointer-offset register still has an unsafe range at the use", "Clamp or branch-check the exact scalar used by this helper, pointer arithmetic, stack access, or map-value access immediately before the rejected operation.", 60, false, true, None, None, None),
    signal_info!(MapPointerArgumentScalarZero, "environment_or_configuration", "map relocation or loader path is missing for a helper map argument", "triage_only", Environment, "verifier_state_signal", "helper expects a map pointer, but verifier state shows scalar zero in the map argument register at the helper call; this matches a missing map relocation or raw-instruction loader path", "Load the ELF object through libbpf or another loader that applies map relocations; raw instructions must not replace a map symbol with scalar zero.", 10, true, true, Some("apply the map relocation so bpf_map_lookup_elem receives a verifier-tracked map pointer instead of scalar zero"), Some("map helper argument is scalar zero because the map relocation was not applied"), Some("BPFIX-E021")),
    signal_info!(BtfFuncInfoMissing, "environment_or_configuration", "BTF function metadata required by a subprogram call is missing", "triage_only", Environment, "verifier_state_signal", "the verifier reports missing BTF func_info while the load log contains a multi-function BPF object or subprogram relocation", "Rebuild and load the object with BTF func_info for BPF subprograms and callbacks; stripped or incomplete BTF metadata can make the verifier reject otherwise valid call shapes.", 10, true, true, Some("provide BTF func_info metadata for every BPF subprogram or callback reached by the loaded program"), Some("BTF func_info metadata is missing for a subprogram call"), Some("BPFIX-E021")),
    signal_info!(SubprogramReferenceMetadataMissing, "source_bug", "subprogram argument reference metadata is missing at the BPF-to-BPF call", "repair_hint", Provenance, "verifier_state_signal", "the BPF-to-BPF call receives a source-level subprogram argument whose verifier reference type is UNKNOWN and has no size metadata", "Use a verifier-supported BPF subprogram argument type instead of erasing the reference through an untyped pointer; keep the argument type metadata visible at the call boundary.", 10, true, true, Some("preserve verifier-visible reference type metadata across the BPF-to-BPF subprogram argument boundary"), Some("subprogram argument reference metadata is missing at this call"), Some("BPFIX-E021")),
    signal_info!(DynptrStackStorageAccess, "source_bug", "dynptr stack storage is being used as ordinary memory", "repair_hint", Protocol, "verifier_state_signal", "verifier state shows this stack slot contains dynptr state, but the rejected instruction reads it as ordinary stack bytes", "Do not copy, read, or pass a dynptr object as ordinary bytes; use dynptr helpers to read data out of the dynptr and keep the dynptr object in its dedicated stack slot.", 10, true, true, Some("keep the dynptr object in its verifier-tracked stack slot and use dynptr helpers instead of reading or copying the dynptr storage as ordinary bytes"), Some("dynptr stack storage is read as ordinary memory"), Some("BPFIX-E012")),
    signal_info!(DynptrUninitializedArgument, "source_bug", "dynptr helper argument is not an initialized verifier-tracked dynptr slot", "repair_hint", Protocol, "verifier_state_signal", "verifier state shows the helper receives a stable stack pointer, but that stack slot is not the current initialized dynptr object", "Initialize the dynptr stack slot through a dynptr creation helper and pass that exact slot to later dynptr helpers; do not pass zeroed, clobbered, or unrelated stack bytes.", 10, false, true, Some("pass the exact verifier-tracked initialized dynptr stack slot to this helper argument"), Some("this helper argument is not an initialized dynptr stack slot"), Some("BPFIX-E012")),
    signal_info!(DynptrReferencedSlotOverwrite, "source_bug", "stack write or helper output overwrites a referenced verifier-tracked dynptr", "repair_hint", Protocol, "verifier_state_signal", "verifier state shows the rejected write target overlaps a dynptr stack slot while a dynptr reference is still live", "Do not overwrite or reinitialize a dynptr stack slot until the verifier-tracked dynptr reference has been submitted, discarded, or otherwise released.", 10, false, true, Some("do not overwrite or reinitialize this dynptr stack slot while its verifier-tracked reference is still live"), Some("this write overwrites a dynptr stack slot with a live reference"), Some("BPFIX-E012")),
    signal_info!(DynptrReadonlyPacketWrite, "source_bug", "writable dynptr slice is requested for packet data in a read-only context", "repair_hint", Environment, "verifier_state_signal", "verifier state traces the dynptr argument back to packet-backed storage before the rejected bpf_dynptr_slice_rdwr call", "Use bpf_dynptr_slice for read-only packet dynptr access, or move writable packet access to a hook and helper combination where packet writes are verifier-allowed.", 10, false, true, Some("use read-only dynptr packet access unless the program context permits writable packet data"), Some("this writable slice request targets a packet-backed dynptr"), Some("BPFIX-E012")),
    signal_info!(DynptrStackSlotWriteOverlap, "source_bug", "helper output or ordinary write overlaps live dynptr stack storage", "repair_hint", Protocol, "verifier_state_signal", "verifier state shows the rejected write target overlaps stack bytes that currently store live dynptr state", "Keep helper output buffers and ordinary writes disjoint from stack bytes that store live dynptr state.", 10, true, true, Some("keep helper output buffers and ordinary writes disjoint from live verifier-tracked dynptr stack slots"), Some("write target overlaps a live dynptr stack slot"), Some("BPFIX-E019")),
    signal_info!(DynptrHelperArgumentStateMismatch, "source_bug", "dynptr helper argument has the wrong stack-slot or backing-memory state", "repair_hint", Protocol, "verifier_state_signal", "verifier state at the dynptr helper call shows an unstable dynptr slot, an interior dynptr pointer, or unsupported stack-backed input memory", "Pass dynptr helpers the exact verifier-tracked stack slot and a supported backing memory object; avoid global dynptr storage, variable stack offsets, and interior dynptr pointers.", 10, true, true, Some("pass dynptr helpers an exact verifier-tracked dynptr stack slot and supported non-stack backing memory"), Some("dynptr helper argument does not match the verifier dynptr contract"), Some("BPFIX-E019")),
    signal_info!(DynptrReleaseUnacquiredReference, "source_bug", "dynptr release helper is called after the dynptr reference was already consumed", "repair_hint", Release, "verifier_state_signal", "verifier state reaches a dynptr release helper with the exact dynptr stack slot but without a live reference", "Release or submit each acquired dynptr exactly once; structure callback and error paths so a consumed dynptr cannot reach another release helper.", 10, true, true, Some("release or submit each verifier-tracked dynptr reference exactly once while the reference is still live"), Some("dynptr release helper is called without a live dynptr reference"), Some("BPFIX-E019")),
    signal_info!(DynptrSliceVariableLength, "source_bug", "dynptr slice length is not verifier-visible as a constant", "repair_hint", Bounds, "verifier_state_signal", "the rejected dynptr slice helper uses R4 as its length argument, but verifier state shows R4 is still a scalar range rather than a known constant", "Use a constant dynptr slice length, or split runtime lengths into verifier-visible constant-size cases before calling the dynptr slice helper.", 10, true, true, Some("pass a verifier-known constant length to the dynptr slice helper"), Some("dynptr slice length argument is not a known constant"), Some("BPFIX-E019")),
    signal_info!(IteratorStackStorageAccess, "source_bug", "iterator state storage is being read as ordinary memory", "repair_hint", Protocol, "verifier_state_signal", "verifier state shows this stack slot contains iterator state, but the rejected instruction reads it as ordinary stack bytes", "Treat iterator stack slots as opaque verifier state; use iterator helpers to read, advance, or destroy the iterator rather than loading the slot bytes directly.", 10, true, true, Some("treat the iterator stack slot as opaque verifier state and access it only through iterator helpers"), Some("iterator state stack slot is read as ordinary memory"), Some("BPFIX-E014")),
    signal_info!(IteratorHelperArgumentStateMismatch, "source_bug", "iterator helper argument has the wrong verifier-tracked lifecycle state", "repair_hint", Protocol, "verifier_state_signal", "the rejected iterator helper receives an argument whose verifier state does not match the helper's required stack iterator lifecycle state", "Keep iterator objects in verifier-tracked stack slots and call iterator create, next, and destroy helpers in the required lifecycle order.", 10, true, true, Some("pass bpf_iter_* helpers a verifier-tracked stack iterator slot in the lifecycle state required by the called helper"), Some("iterator helper argument has the wrong lifecycle state"), Some("BPFIX-E014")),
    signal_info!(IrqFlagStateMismatch, "source_bug", "IRQ flag helper argument has the wrong verifier-tracked lifecycle state", "repair_hint", Protocol, "verifier_state_signal", "the rejected IRQ helper receives a stack slot whose verifier state does not match the helper's save/restore lifecycle contract", "Keep each IRQ flag stack slot dedicated to one save/restore pair, and pass restore the exact slot initialized by the matching save helper.", 10, true, true, Some("pass bpf_local_irq_save an empty stack flag slot and pass bpf_local_irq_restore the same verifier-tracked flag slot produced by save"), Some("IRQ flag helper argument has the wrong lifecycle state"), Some("BPFIX-E020")),
    signal_info!(IrqRestoreOrderMismatch, "source_bug", "IRQ state is restored outside the verifier-approved acquisition order", "repair_hint", Protocol, "verifier_state_signal", "verifier state reaches an IRQ restore helper with a live IRQ flag slot while the verifier expects a newer outstanding IRQ state", "Restore IRQ save and lock state in strict reverse acquisition order, using the same flag slot returned by each save or lock helper.", 10, true, true, Some("restore each verifier-tracked IRQ state in strict LIFO order with the flag slot produced by its matching save or lock helper"), Some("IRQ restore uses a flag slot before newer IRQ state is restored"), Some("BPFIX-E013")),
    signal_info!(IrqRestoreHelperClassMismatch, "source_bug", "IRQ restore helper class does not match the verifier-tracked state", "repair_hint", Protocol, "verifier_state_signal", "verifier state reaches an IRQ restore helper whose class does not match the newest live IRQ state origin", "Restore lock-acquired IRQ state with bpf_res_spin_unlock_irqrestore, and plain local IRQ state with bpf_local_irq_restore, in strict LIFO order.", 10, true, true, Some("restore each verifier-tracked IRQ state with the helper class that matches the save or lock helper that created it"), Some("IRQ restore helper class does not match live state origin"), Some("BPFIX-E013")),
    signal_info!(IrqStateLiveAtExit, "source_bug", "program exits while verifier-tracked IRQ state is still live", "repair_hint", Protocol, "verifier_state_signal", "verifier state reaches BPF_EXIT with live IRQ save references that have not been restored", "Restore every verifier-tracked IRQ save state before returning or exiting, including states acquired inside BPF subprogram helpers.", 10, true, true, Some("restore every verifier-tracked IRQ save state before any BPF_EXIT can leave the program"), Some("BPF_EXIT is reached while IRQ save state is still live"), Some("BPFIX-E013")),
    signal_info!(SleepableCallInNonSleepableContext, "source_bug", "sleepable helper or subprogram call reaches a non-sleepable verifier context", "repair_hint", Context, "verifier_state_signal", "verifier state reaches a sleepable helper or subprogram call while IRQ, RCU, preempt, or program-context rules require non-sleepable execution", "Move sleepable helper or global-subprogram calls outside IRQ/RCU/preempt-disabled regions, or use only non-sleepable operations from this program context.", 7, true, true, Some("prove the sleepable helper or subprogram call cannot run in a non-sleepable IRQ, RCU, preempt-disabled, or program-context region"), Some("sleepable call is reachable from a non-sleepable verifier context"), Some("BPFIX-E016")),
    signal_info!(CallbackCallWhileLocked, "source_bug", "callback-invoking operation runs while a spin lock is held", "repair_hint", Protocol, "verifier_state_signal", "verifier branch state enters a synchronous callback from a call made after bpf_spin_lock and before the matching unlock", "Move callback-invoking operations such as rbtree insertion outside spin-locked regions, or release the lock before a callback path can call helpers, kfuncs, or bpf_throw.", 10, true, true, Some("avoid entering verifier callback frames from operations executed while a spin lock is held"), Some("callback path can run a forbidden call while a spin lock is held"), Some("BPFIX-E015")),
    signal_info!(NullablePointerUseWithoutProof, "source_bug", "nullable pointer is used before the verifier sees a non-null proof", "repair_hint", Null, "verifier_state_signal", "verifier state shows the rejected pointer register is still a nullable helper result at the dereference, arithmetic, or helper-use site", "Check the helper result for null and keep the dereference, pointer arithmetic, or helper argument inside the same verifier-visible non-null branch.", 10, false, true, Some("prove the nullable helper result is non-null in the same verifier-visible branch as this use"), Some("nullable pointer reaches this use without a non-null proof"), Some("BPFIX-E002")),
    signal_info!(NullScalarDereferenceAfterPointerProof, "source_bug", "a previously pointer-like value is dereferenced after becoming scalar zero", "repair_hint", Null, "verifier_state_signal", "verifier state shows the rejected base register is exact scalar zero after an earlier nullable or pointer-like proof, so the access is on the null side of the proof lifecycle", "Keep dereferences on the verifier-visible non-null branch, and revalidate the pointer immediately before use if a loop, helper, or branch can replace it with NULL.", 10, false, false, Some("prove this dereference is reachable only when the pointer-like value is non-null and has not been overwritten with scalar zero"), Some("this access dereferences the scalar-zero side of an earlier pointer proof"), Some("BPFIX-E011")),
    signal_info!(TrustedNullableArgument, "source_bug", "trusted helper argument is still verifier-visible as nullable", "repair_hint", Null, "verifier_state_signal", "verifier state shows the rejected helper or kfunc argument is still a nullable RCU/trusted pointer at the call site", "Keep the RCU or trusted-pointer argument inside the verifier-visible non-null branch, or acquire a trusted reference before passing it to the helper or kfunc.", 10, true, true, Some("prove the RCU/trusted pointer argument is non-null and trusted at the helper or kfunc call site"), Some("trusted helper argument remains nullable at the call site"), Some("BPFIX-E015")),
    signal_info!(KfuncArgumentTypeMismatch, "source_bug", "kfunc argument does not have the verifier-required object or reference type", "repair_hint", Protocol, "verifier_state_signal", "verifier state shows the rejected kfunc argument is a different pointer class than the kfunc contract requires", "Pass kfuncs the exact verifier-owned object type they require; do not cast stack memory, walked struct members, or plain kernel objects into BPF-owned kfunc object types.", 10, false, true, Some("pass the kfunc a verifier-tracked object or reference whose BTF and ownership class exactly matches the kfunc argument contract"), Some("kfunc argument has the wrong verifier object type"), Some("BPFIX-E013")),
    signal_info!(VerifierTypeContractMismatch, "source_bug", "helper or kfunc argument has the wrong verifier-visible type", "repair_hint", Protocol, "verifier_state_signal", "verifier state at the call site confirms the rejected argument register has the printed actual type, while the helper or kfunc contract requires a different verifier-visible type", "Pass the helper or kfunc the exact verifier-visible argument type it requires; use a real map pointer, stack pointer, packet pointer, ringbuf memory pointer, or trusted object pointer rather than casting or reusing a different pointer class.", 12, false, true, Some("pass the helper or kfunc argument register the exact verifier-visible type required by its contract at this call site"), Some("helper or kfunc argument has the wrong verifier-visible type"), Some("BPFIX-E008")),
    signal_info!(ModernBpfObjectProtocolViolation, "source_bug", "modern BPF object helper or kfunc argument violates its verifier object protocol", "repair_hint", Protocol, "verifier_state_signal", "verifier state shows a modern BPF object protocol helper received a non-owned, non-RCU, non-referenced, or invalid cgroup, cpumask, kptr, or skb object argument", "Pass modern BPF object helpers and kfuncs only verifier-owned, RCU-protected, referenced, or valid kptr-storage objects as required by the specific helper contract.", 8, false, true, Some("pass the helper or kfunc a verifier-approved object: valid kptr storage, a referenced/trusted object, or an RCU-protected object in the required state"), Some("modern BPF object argument violates its verifier protocol"), Some("BPFIX-E023")),
    signal_info!(ContextAccessSourceArgumentMismatch, "source_bug", "tracing context argument type does not match the verifier-visible function signature", "repair_hint", Context, "verifier_state_signal", "verifier reports the traced-function argument at this context slot as PTR rather than a directly supported struct pointer, while the rejected source is a BPF_PROG argument load from the raw tracing context", "Use only fentry arguments whose BTF type is verifier-supported at this slot, or avoid reading this argument through BPF_PROG when the traced function exposes it as an unsupported pointer type.", 10, true, true, None, None, None),
    signal_info!(TraceContextScalarArgumentMismatch, "source_bug", "tracepoint context field is scalar in verifier state but used as a typed pointer", "repair_hint", Context, "verifier_state_signal", "tracepoint/raw-tracepoint context field produced a scalar where the source treats it as a typed pointer", "Use the tracepoint or raw-tracepoint context ABI directly: treat ctx fields such as args/envp/argv/filename as scalar values until a verifier-approved helper or context contract turns them into readable memory.", 10, true, true, Some("use the tracepoint or raw-tracepoint context ABI before treating context fields as typed pointers"), Some("tracepoint context field is scalar in verifier state but typed as a pointer in source"), Some("BPFIX-E011")),
    signal_info!(ContextFieldUnavailable, "environment_or_configuration", "program context field is unavailable for the active verifier context", "repair_hint", Context, "verifier_state_signal", "verifier state shows the rejected memory access uses a ctx register at an offset and width that the active program context does not expose", "Use a program type or attach type that exposes this context field, read a verifier-supported context field, or derive the value from packet data instead of an unavailable context slot.", 10, false, true, Some("access only context offsets and field widths exposed by the active BPF program type and attach point"), Some("context access uses an unavailable offset or field width"), None),
    signal_info!(PacketContextFieldAccessInUnsupportedProgram, "source_bug", "packet context fields are read from a program type that does not expose packet pointers", "repair_hint", Environment, "verifier_state_signal", "object section metadata identifies a non-packet program while verifier state shows the rejected pointer came from __sk_buff packet data/data_end offsets that are scalar in that context", "Move direct packet parsing to XDP, TC, classifier, or another packet program type that exposes packet pointers; otherwise read the traced kernel object through a verifier-approved helper.", 10, false, true, Some("use an attach/program type that exposes verifier-tracked packet data/data_end pointers before doing direct packet parsing"), Some("packet data/data_end fields are scalar in this program section"), Some("BPFIX-E011")),
    signal_info!(KernelObjectFieldAccessMismatch, "source_bug", "kernel object field access targets a different struct than the verifier-visible pointer", "repair_hint", Context, "verifier_state_signal", "verifier state shows the base register is a kernel object pointer for the reported struct, while CO-RE relocation metadata targets a different struct at the rejected offset", "Read the field through a verifier-supported kernel-memory access path such as BPF_CORE_READ, instead of directly casting a verifier-visible kernel object pointer to a larger or different struct.", 10, false, true, Some("read the kernel field through a verifier-supported helper or CO-RE access path instead of directly loading a field outside the verifier-visible object type"), Some("this load reads a field outside the verifier-visible kernel object type"), Some("BPFIX-E011")),
    signal_info!(ExceptionThrowWithLiveReference, "source_bug", "exception callback can throw while a verifier-tracked reference is still live", "repair_hint", Release, "verifier_state_signal", "verifier state reaches bpf_throw inside a callback frame while verifier-tracked references are live", "Release verifier-tracked references before any callback path can throw, or avoid bpf_throw while a reference acquired by the caller is still live.", 10, true, true, Some("release verifier-tracked references on every callback and exceptional path before bpf_throw can run"), Some("bpf_throw can run while verifier-tracked references are live"), Some("BPFIX-E004")),
    signal_info!(ReferenceLiveAtExit, "source_bug", "program exits while a verifier-tracked reference is still live", "repair_hint", Release, "verifier_state_signal", "verifier state reaches BPF_EXIT with the terminal reference id still live in the refs set", "Release every verifier-tracked reference on all return paths; route success and error exits through cleanup blocks that release the exact live reference id before BPF_EXIT.", 10, true, true, Some("release every verifier-tracked reference before each BPF_EXIT path can leave the program"), Some("this exit is reachable with a verifier-tracked reference still live"), Some("BPFIX-E004")),
    signal_info!(ExceptionCallbackProtocolViolation, "source_bug", "subprogram or exception callback protocol contract is violated", "repair_hint", Protocol, "verifier_state_signal", "verifier log validates a BPF subprogram or exception callback whose call path or return value violates the verifier protocol", "Keep exception callbacks out of ordinary subprogram call graphs, and make subprogram or callback returns satisfy the verifier's printed return-value contract.", 10, false, true, Some("keep exception callbacks reachable only through the verifier exception machinery and make subprogram or callback returns satisfy the verifier's printed return-value contract"), Some("subprogram or exception callback violates the verifier-approved protocol"), Some("BPFIX-E013")),
    signal_info!(MapLookupKeyArgumentUnreadable, "source_bug", "map lookup key pointer argument is unreadable", "repair_hint", Initialize, "verifier_state_signal", "bpf_map_lookup_elem consumes R2 as the key pointer, but verifier state reports that this helper argument register is not readable", "Pass bpf_map_lookup_elem a pointer to initialized key storage, such as &key for a local key variable, not an uninitialized key pointer.", 10, true, true, Some("pass a pointer to initialized map key storage in bpf_map_lookup_elem's second argument"), Some("map lookup key argument register is unreadable at the helper call"), None),
    signal_info!(UnreadableProgramEntryArgument, "source_bug", "program entry argument register is unreadable in verifier state", "repair_hint", Context, "verifier_state_signal", "verifier entry state exposes only the program context and frame pointer, but the rejected instruction reads an entry argument register this program ABI did not provide", "Use the verifier-supported program ABI: read kprobe/syscall arguments from ctx or pt_regs helpers, or use a supported BPF_PROG-style wrapper.", 10, false, true, Some("use the program-type context ABI instead of reading an entry argument register the verifier did not provide"), Some("this argument register is not readable in verifier state"), Some("BPFIX-E011")),
    signal_info!(UnreadableHelperArgument, "source_bug", "helper argument register is unreadable at the call site", "repair_hint", Initialize, "verifier_state_signal", "the rejected helper call consumes an argument register that has no verifier-readable state at the call site", "Set the helper argument register to a verifier-readable value immediately before the helper call, or remove the helper path that reaches the call without that argument.", 10, false, true, Some("set the rejected helper argument register to a verifier-readable value on every path before the helper call"), Some("this helper argument register is not readable at the call"), Some("BPFIX-E010")),
    signal_info!(MapPointerRawAccessContract, "source_bug", "map pointer is accessed as ordinary memory", "repair_hint", Protocol, "verifier_state_signal", "verifier state shows an ordinary memory access whose base register is a map_ptr, but map contents must be reached through a helper-returned map-value pointer", "Look up an element and read or write the returned map-value pointer; do not dereference or store through the map object pointer itself.", 10, false, true, Some("derive a verifier-visible map-value pointer with the proper map helper before reading or writing map contents"), Some("this memory access uses the map object pointer as ordinary memory"), Some("BPFIX-E010")),
    signal_info!(PerfEventOutputPacketAccess, "source_bug", "perf event output helper receives packet memory directly", "repair_hint", Protocol, "verifier_state_signal", "verifier state at bpf_perf_event_output passes a packet pointer and scalar length as the data/size pair, but this helper cannot read packet memory directly", "Copy packet bytes into stack or map storage first, or use a helper path that supports packet data instead of passing the packet pointer directly as the perf-event payload.", 10, false, true, Some("pass bpf_perf_event_output helper-readable stack or map memory, not a live packet pointer, as its data payload"), Some("this helper call passes packet memory as the output payload"), Some("BPFIX-E010")),
    signal_info!(UnreadableReturnRegister, "source_bug", "return register is unreadable at BPF_EXIT", "repair_hint", Initialize, "verifier_state_signal", "terminal verifier state rejects BPF_EXIT because the return register is not readable", "Initialize R0 with a valid return code on every path before returning from the BPF program.", 10, false, true, Some("initialize R0 to a verifier-readable return value before BPF_EXIT"), Some("this exit has no readable value in R0"), Some("BPFIX-E003")),
    signal_info!(LegacySkbLoadUnreadableRegister, "source_bug", "legacy skb load reads an implicit unreadable register", "repair_hint", Context, "verifier_state_signal", "verifier state for this legacy skb load has no readable state for the instruction's implicit skb register", "Use verifier-recognized pointer or context access patterns instead of classic skb[] inline-assembly loads; do not rely on implicit registers outside the program ABI.", 10, false, true, Some("use verifier-recognized pointer or context access instead of a legacy skb[] load with an implicit unreadable register"), Some("this legacy skb load uses an implicit unreadable register"), Some("BPFIX-E003")),
    signal_info!(HelperStackReadLengthExceedsInitializedRange, "source_bug", "helper memory/length pair length exceeds the initialized stack prefix", "repair_hint", Bounds, "verifier_state_signal", "verifier state shows the helper receives a stack pointer with an initialized byte prefix, but the helper length extends past that prefix", "Clamp or reduce the helper length to the initialized stack buffer size, or initialize the full byte range before passing it to the helper.", 9, false, true, Some("prove the helper memory length stays within the stack bytes initialized at the pointer argument"), Some("this helper length extends past the initialized stack buffer"), Some("BPFIX-E003")),
    signal_info!(HelperStackReadExceedsInitializedRange, "source_bug", "helper memory/length pair reads unwritten stack bytes", "repair_hint", Initialize, "verifier_state_signal", "verifier state shows the helper receives a stack pointer and length whose access range extends past the stack bytes proven written at that pointer", "Write every byte in the helper access range before the call, or reduce the length passed with the stack pointer.", 10, false, true, Some("prove every byte in the helper memory/length pair access range is written before the call"), Some("this helper reads unwritten stack bytes"), Some("BPFIX-E003")),
    signal_info!(HelperStackWriteBeyondFrame, "source_bug", "helper writable stack region crosses the verifier stack frame", "repair_hint", Bounds, "verifier_state_signal", "verifier state shows the helper receives a frame-pointer stack region whose byte range extends beyond the BPF stack frame", "Move large scratch buffers to a per-CPU map, shrink the stack object, or pass a smaller helper length so the writable region stays inside the 512-byte BPF stack frame.", 10, false, true, Some("keep the helper writable stack range fully inside the current BPF stack frame, whose valid byte offsets are -512..0"), Some("this helper write crosses the verifier stack frame boundary"), Some("BPFIX-E006")),
    signal_info!(ScalarValueUsedAsPointer, "source_bug", "scalar or pkt_end value is used where the verifier requires a real pointer", "repair_hint", Provenance, "verifier_state_signal", "verifier state at the rejected instruction shows the consumed register is scalar or pkt_end state, but the instruction uses it as a memory pointer or pointer-like value", "Use a verifier-recognized pointer at the access site; keep end sentinels, scalar offsets, and pointer bases separate, and reload or rederive the pointer from a supported context/helper before dereferencing it.", 10, false, true, Some("prove the value consumed by this memory access or pointer operation is a verifier-recognized pointer, not scalar or pkt_end state"), Some("this access consumes scalar or pkt_end state where a pointer is required"), Some("BPFIX-E011")),
    signal_info!(OpaqueScalarPointerDereference, "source_bug", "opaque pointer-sized helper output is dereferenced as ordinary memory", "repair_hint", Protocol, "verifier_state_signal", "verifier state shows the rejected scalar value was loaded from helper-written stack storage, so any kernel or user memory it denotes still must be read through a verifier-approved helper", "Treat pointer-sized values read with bpf_probe_read* or BPF_CORE_READ as opaque scalars; use another helper read to copy the memory they denote into stack or map storage before inspecting it.", 10, false, false, Some("read the memory referenced by this opaque scalar pointer through a verifier-approved helper instead of directly dereferencing it"), Some("this access dereferences an opaque scalar pointer loaded from helper output"), Some("BPFIX-E011")),
    signal_info!(StalePointerAfterInvalidatingHelper, "source_bug", "skb/xdp packet pointer is reused after a helper invalidates it", "repair_hint", Provenance, "verifier_state_signal", "verifier state shows this register previously held an skb/xdp packet pointer, but an intervening packet-mutating helper invalidated that pointer before the rejected memory access", "After helpers that move or rewrite skb/xdp data, reload packet data/data_end, recheck the packet range, and derive a fresh packet pointer before dereferencing.", 10, false, true, Some("preserve pointer provenance by reacquiring and rechecking the skb/xdp packet pointer after the helper that invalidates existing packet data pointers"), Some("this access reuses a pointer invalidated by an earlier helper call"), Some("BPFIX-E011")),
    signal_info!(DynptrDataPointerInvalidatedBeforeUse, "source_bug", "dynptr data or slice pointer is reused after verifier-visible invalidation", "repair_hint", Protocol, "verifier_state_signal", "verifier state traces this register to a dynptr data or slice helper result, then sees a later helper or callback write invalidate the underlying dynptr or packet backing before the rejected memory access", "Treat dynptr data and slice pointers as invalid after helpers, callback writes, or packet operations that can mutate their backing storage; reacquire a fresh dynptr data or slice pointer before dereferencing.", 10, false, true, Some("follow the dynptr data/slice lifecycle by discarding invalidated data pointers and reacquiring a fresh verifier-tracked slice after the invalidating helper or callback write"), Some("this access reuses a dynptr data pointer after invalidation"), Some("BPFIX-E011")),
    signal_info!(ProhibitedPointerArithmetic, "source_bug", "pointer arithmetic uses an operator the verifier cannot apply to pointer state", "repair_hint", Provenance, "verifier_state_signal", "verifier state at the rejected instruction shows the target register is still pointer state, but the instruction applies a prohibited pointer arithmetic or bitwise operator", "Avoid bitwise or unsupported arithmetic on pointer registers; preserve pointer provenance by keeping the pointer unchanged and applying scalar arithmetic to a separate offset before deriving a verifier-recognized pointer.", 10, false, true, Some("preserve pointer state by avoiding bitwise or verifier-prohibited arithmetic on the pointer register"), Some("this instruction applies a prohibited operation to pointer state"), None),
    signal_info!(PacketGuardUndercoversAccess, "source_bug", "packet bounds check is narrower than the later packet access", "repair_hint", Bounds, "verifier_state_signal", "source has a packet bounds check, but verifier state after that check proves only a shorter packet range than the rejected access needs", "Move the data_end check to the final pointer expression and include the access width, for example check pointer + size before dereferencing pointer.", 40, true, false, None, None, None),
    signal_info!(PacketMaxOffsetPrecisionBoundary, "verifier_false_positive", "verifier precision limit may hide an existing safety proof", "triage_only", Bounds, "verifier_precision_signal", "verifier state reaches a packet access with a large variable offset range at the packet-offset precision boundary", "Treat this as a verifier precision boundary: clamp the packet cursor to a verifier-friendly maximum before the loop, then rederive and recheck the exact byte pointer used by the load.", 30, true, false, None, None, None),
    signal_info!(MapValueRelationPrecisionBoundary, "verifier_false_positive", "verifier precision limit may hide an existing safety proof", "triage_only", Bounds, "verifier_precision_signal", "source-level map-value bounds guard is present, but the verifier appears to lose a cross-variable range relation", "Make the remaining map-value capacity explicit in one bounded variable, clamp the helper length to that variable, and pass that same value to the helper.", 4, true, false, None, None, None),
];

#[cfg(test)]
pub(super) fn metadata_signals_for_test() -> impl Iterator<Item = ProofSignal> {
    SIGNAL_INFOS.iter().map(|info| info.signal)
}

impl ProofSignal {
    fn info(self) -> &'static SignalInfo {
        SIGNAL_INFOS
            .iter()
            .find(|info| info.signal == self)
            .expect("every ProofSignal variant must have metadata")
    }

    pub(crate) fn failure_class(self) -> &'static str {
        self.info().failure_class
    }

    pub(crate) fn summary(self) -> &'static str {
        self.info().summary
    }

    pub(crate) fn help_safety(self) -> &'static str {
        self.info().help_safety
    }

    pub(crate) fn next_action(self) -> NextAction {
        self.info().next_action
    }

    pub(crate) fn evidence_kind(self) -> &'static str {
        self.info().evidence_kind
    }

    pub(crate) fn evidence_detail(self) -> &'static str {
        self.info().evidence_detail
    }

    pub(crate) fn help(self) -> &'static str {
        self.info().help
    }

    pub(crate) const fn confidence(self) -> &'static str {
        "medium"
    }

    pub(super) fn selection_rank(self) -> u8 {
        self.info().selection_rank
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

    pub(crate) fn can_replace_unsupported_terminal(self) -> bool {
        self.info().can_replace_unsupported_terminal
    }

    pub(crate) fn replaces_classifier_help(self) -> bool {
        self.info().replaces_classifier_help
    }

    pub(crate) fn required_proof_override(self) -> Option<&'static str> {
        self.info().required_proof_override
    }

    pub(crate) fn primary_label_override(self) -> Option<&'static str> {
        self.info().primary_label_override
    }

    pub(crate) fn error_id_override(self) -> Option<&'static str> {
        self.info().error_id_override
    }
}
