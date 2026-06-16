use super::{
    callback_signal, context_signal, dynptr_signal, fallback_pointer_signal,
    helper_contract_signal, irq_signal, iterator_signal, lowering_signal, map_value_signal,
    nullable_signal, opaque_pointer_signal, packet_signal, protocol_signal, scalar_range_signal,
    stack_signal, stale_pointer_signal, type_contract_signal, ProofSignal, ProofSignalContext,
};

#[rustfmt::skip]
pub(super) fn proof_signals(context: ProofSignalContext<'_>) -> Vec<ProofSignal> {
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
        ProofSignal::WideStackAlignment => lowering_signal::stack_alignment_lowering_signal(c),
        ProofSignal::AtomicMemoryAccessScalarBase => lowering_signal::atomic_memory_alignment_scalar_base(c),
        ProofSignal::LoopBackEdgeStateRepeats => lowering_signal::loop_back_edge_state_repeats(c),
        ProofSignal::PointerShiftDropsProvenance => lowering_signal::pointer_shift_lowering_signal(c),
        ProofSignal::ModifiedContextPointer => lowering_signal::modified_context_pointer_lowering_signal(c),
        ProofSignal::SharedInstructionPointerMerge => lowering_signal::shared_instruction_pointer_merge_signal(c),
        ProofSignal::SubprogramContextArgumentDropped => lowering_signal::subprogram_context_argument_dropped_signal(c),
    }
    if c.source_events.is_empty() {
        push_optional_signals!(lowering_signal::bytecode_only_lowering_signal(c.log, c.terminal_error, c.obligation, c.terminal_pc, c.register, c.states));
    }
    push_optional_signals!(map_value_signal::verifier_precision_signal(c), packet_signal::verifier_precision_signal(c));

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
        ProofSignal::HelperStackReadLengthExceedsInitializedRange => stack_signal::helper_stack_read_length_exceeds_initialized_range(c),
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
        ProofSignal::CallbackCallWhileLocked => callback_signal::callback_call_while_locked(c),
        ProofSignal::NullablePointerUseWithoutProof => nullable_signal::nullable_pointer_use_without_proof(c),
        ProofSignal::ModernBpfObjectProtocolViolation => protocol_signal::modern_bpf_object_protocol_violation(c),
        ProofSignal::KfuncArgumentTypeMismatch => type_contract_signal::kfunc_argument_type_mismatch(c),
        ProofSignal::TrustedNullableArgument => nullable_signal::trusted_nullable_argument(c),
        ProofSignal::VerifierTypeContractMismatch => type_contract_signal::verifier_type_contract_mismatch(c),
        ProofSignal::MemoryObjectAccessOutOfBounds => scalar_range_signal::memory_object_access_out_of_bounds(c),
        ProofSignal::ReturnRangeOutOfBounds => scalar_range_signal::return_range_out_of_bounds(c),
        ProofSignal::StackVariableOffsetOutOfBounds => scalar_range_signal::stack_variable_offset_out_of_bounds(c),
        ProofSignal::ScalarRangeUnsafeAtUse => scalar_range_signal::scalar_range_unsafe_at_use(c),
        ProofSignal::PacketPointerProofLostAfterBoundsCheck => packet_signal::packet_pointer_proof_lost_after_bounds_check(c.events),
        ProofSignal::PacketRangeProofLostBeforeAccess => packet_signal::packet_range_proof_lost_before_access(c.events),
        ProofSignal::PacketGuardUndercoversAccess => packet_signal::packet_guard_undercovers_access(c),
        ProofSignal::PacketAccessWithoutBoundsProof => packet_signal::packet_access_without_bounds_proof(c),
        ProofSignal::MapValueWideAccess => map_value_signal::map_value_wide_access(c.log, c.terminal_error, c.terminal_pc, c.terminal_line, c.register, c.branch_states),
        ProofSignal::MapValueCheckedOffsetRelationLost => map_value_signal::map_value_checked_offset_relation_lost(c.terminal_error, c.terminal_pc, c.register, c.states, c.events, c.source_events),
        ProofSignal::MapValueGuardExceedsValueSize => map_value_signal::map_value_guard_exceeds_value_size(c),
        ProofSignal::MapValueAccessOutOfBounds => map_value_signal::map_value_access_out_of_bounds(c),
    }

    push_fallback_opt!(stale_pointer_signal::stale_pointer_after_invalidating_helper(c));
    push_fallback_signal!(ProofSignal::OpaqueScalarPointerDereference => opaque_pointer_signal::opaque_scalar_pointer_dereference(c));
    push_fallback_signal!(ProofSignal::NullScalarDereferenceAfterPointerProof => nullable_signal::null_scalar_dereference_after_pointer_proof(c));
    push_fallback_signal!(ProofSignal::ScalarValueUsedAsPointer => fallback_pointer_signal::scalar_value_used_as_pointer(c));
    push_fallback_signal!(ProofSignal::ProhibitedPointerArithmetic => fallback_pointer_signal::prohibited_pointer_arithmetic(c));

    // Same-rank signals keep registry order; runtime selection relies on stable sorting.
    signals.sort_by_key(|signal| signal.selection_rank());
    signals
}
