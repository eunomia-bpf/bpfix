use anyhow::Result;
use bpfanalysis::helper_abi::helper_dynptr_initializer_output_arg;
use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, instruction_site_before_line, instructions_in_line_range,
    latest_reg_state_before_instruction, latest_reg_state_before_instruction_with_origin,
    latest_reg_state_for_call_argument, latest_reg_state_for_call_argument_with_frame,
    latest_register_assignment, loose_register_operands as register_operands,
    memory_access_base_register, reg_state_has_variable_offset,
    register_from_verifier_error as register_from_terminal_error, stack_value_range,
    terminal_instruction_site, verifier_fragment_start_line,
    verifier_states_with_branch_deltas_from_log, CallbackKind, RegState, StackByteRange,
    VerifierInsn, VerifierInsnKind, VerifierLogInstruction as TerminalInstruction,
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

mod context_signal;
mod dynptr_signal;
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
mod signal;
mod source_query;
mod stack_access;
mod stack_signal;
mod stale_pointer_signal;
mod type_contract_signal;
pub use signal::ProofSignal;
use source_query::{
    call_argument, first_call_argument, identifier_tokens, invalid_args_function_name,
    is_bare_identifier_argument, looks_like_packet_pointer_derivation,
    map_argument_has_relocation_proof, max_numeric_token, numeric_tokens, rejected_source,
    same_source_location, source_for_instruction_in_fragment, source_for_pc_in_rejected_file,
};

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
    let signals = proof_signals(signal_context);

    Ok(VerifierLogAnalysis {
        state_count: states.len(),
        required_proof,
        events,
        signals,
    })
}

fn is_pointer_state(state: &RegState) -> bool {
    state.reg_type != "scalar" && state.reg_type != "fp"
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
    push_fallback_signal!(ProofSignal::ScalarValueUsedAsPointer => scalar_value_used_as_pointer(c));
    push_fallback_signal!(ProofSignal::ProhibitedPointerArithmetic => prohibited_pointer_arithmetic(c));

    // Same-rank signals keep registry order; runtime selection relies on stable sorting.
    signals.sort_by_key(|signal| signal.selection_rank());
    signals
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DynptrStackSlot {
    frame: usize,
    offset: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DynptrBacking {
    Packet,
    Memory,
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
            let arg_reg = helper_dynptr_initializer_output_arg(target)?;
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

fn terminal_call_instruction_site<'a>(
    context: &'a ProofSignalContext<'a>,
) -> Option<TerminalInstruction<'a>> {
    bpfanalysis::verifier_log::terminal_or_nearest_call_instruction_site(
        context.log,
        context.terminal_pc,
        context.terminal_line,
        context.terminal_call_target,
    )
}

fn terminal_error_has_nearby_prior_line(
    log: &str,
    terminal_error: &str,
    terminal_line: Option<usize>,
    lookback: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let lines = log.lines().collect::<Vec<_>>();
    if let Some((line, idx)) = terminal_line.and_then(|line| Some((line, line.checked_sub(1)?))) {
        let fragment_start = verifier_fragment_start_line(log, line).saturating_sub(1);
        let lookback_start = idx.saturating_sub(lookback).max(fragment_start);
        return lines.get(idx).is_some_and(|line| {
            line.contains(terminal_error)
                && lines[lookback_start..idx]
                    .iter()
                    .any(|prior| predicate(prior))
        });
    }
    lines.iter().enumerate().any(|(idx, line)| {
        line.contains(terminal_error)
            && lines[idx.saturating_sub(lookback)..idx]
                .iter()
                .any(|prior| predicate(prior))
    })
}

#[cfg(test)]
mod tests;
