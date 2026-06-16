use bpfanalysis::helper_abi::{
    helper_dynptr_data_invalidating_arg, helper_dynptr_data_producer_arg,
};
use bpfanalysis::verifier_log::{
    call_target_from_instruction_tail, instruction_single_register_rhs_source,
    instruction_site_before_line, instructions_in_line_range,
    latest_reg_state_before_instruction_with_frame,
    latest_reg_state_before_instruction_with_origin, latest_verifier_state_before_instruction,
    memory_access_base_register, memory_access_is_store, reg_state_has_variable_offset,
    register_assigned_between, stack_memory_access_range, stack_value_range,
    terminal_instruction_site, verifier_fragment_start_line, CallbackKind, RegState,
    StackByteRange, VerifierInsn, VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;

use super::{
    dynptr_slot_backing_before, dynptr_stack_slot_for_call_argument, register_from_terminal_error,
    terminal_fragment_start, DynptrBacking, DynptrStackSlot, ProofSignal, ProofSignalContext,
};

pub(super) fn stale_pointer_after_invalidating_helper(
    context: &ProofSignalContext<'_>,
) -> Option<ProofSignal> {
    if context.obligation != ProofObligation::PointerProvenance {
        return None;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid mem access 'scalar'")
        || terminal.contains("invalid mem access 'inv'"))
    {
        return None;
    }
    let reg = context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))?;
    let instruction =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)?;
    if memory_access_base_register(instruction.tail) != Some(reg) {
        return None;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let (state, state_log_line, state_frame) = latest_reg_state_before_instruction_with_origin(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    )?;
    let (pointer_kind, invalidated) = if let Some(pointer_kind) =
        stale_data_pointer_kind(context, state, state_log_line, reg)
    {
        if register_assigned_between(
            context.branch_states,
            context.log,
            reg,
            state_frame,
            fragment_start,
            state_log_line,
            instruction.line,
        ) {
            return None;
        }
        let invalidated =
            invalidating_helper_between(context, state_log_line, instruction.line, pointer_kind)
                || matches!(
                    pointer_kind,
                    StaleDataPointerKind::DynptrData(origin)
                        if dynptr_data_invalidated_by_callback_write(
                            context,
                            state_log_line,
                            instruction.line,
                            origin,
                        )
                );
        (pointer_kind, invalidated)
    } else {
        let (origin, origin_log_line) = prior_dynptr_data_pointer_before_instruction(
            context,
            instruction,
            fragment_start,
            reg,
        )?;
        if !dynptr_data_invalidated_by_callback_write(
            context,
            origin_log_line,
            instruction.line,
            origin,
        ) {
            return None;
        }
        (StaleDataPointerKind::DynptrData(origin), true)
    };
    if !invalidated {
        return None;
    }
    Some(match pointer_kind {
        StaleDataPointerKind::Packet => ProofSignal::StalePointerAfterInvalidatingHelper,
        StaleDataPointerKind::DynptrData(_) => ProofSignal::DynptrDataPointerInvalidatedBeforeUse,
    })
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

fn prior_dynptr_data_pointer_before_instruction(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    reg: u8,
) -> Option<(DynptrDataOrigin, usize)> {
    context
        .branch_states
        .iter()
        .filter(|state| state.log_line >= fragment_start)
        .filter(|state| state.log_line < instruction.line)
        .filter(|state| state.pc <= instruction.pc)
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            if !matches!(reg_state.reg_type.as_str(), "mem" | "rdonly_mem") {
                return None;
            }
            if register_assigned_between(
                context.branch_states,
                context.log,
                reg,
                state.frame,
                fragment_start,
                state.log_line,
                instruction.line,
            ) {
                return None;
            }
            Some((
                dynptr_data_origin(context, state.log_line, reg)?,
                state.log_line,
            ))
        })
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
    instructions_in_line_range(context.log, after_line.saturating_add(1), before_line)
        .filter_map(|instruction| {
            let target = call_target_from_instruction_tail(instruction.tail)?;
            Some((instruction, target))
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

fn dynptr_data_origin(
    context: &ProofSignalContext<'_>,
    before_line: usize,
    reg: u8,
) -> Option<DynptrDataOrigin> {
    let fragment_start = verifier_fragment_start_line(context.log, before_line);
    let mut current_reg = reg;
    let instructions =
        instructions_in_line_range(context.log, fragment_start, before_line.saturating_add(1))
            .collect::<Vec<_>>();
    for instruction in instructions.iter().rev().copied() {
        if let Some(source_reg) =
            instruction_single_register_rhs_source(instruction.tail, current_reg)
        {
            current_reg = source_reg;
            continue;
        }
        let target = call_target_from_instruction_tail(instruction.tail);
        if current_reg != 0 {
            continue;
        }
        let Some(target) = target else {
            continue;
        };
        let arg_reg = helper_dynptr_data_producer_arg(target)?;
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

fn dynptr_data_invalidated_by_call(
    context: &ProofSignalContext<'_>,
    instruction: TerminalInstruction<'_>,
    target: &str,
    origin: DynptrDataOrigin,
) -> bool {
    let Some(arg_reg) = helper_dynptr_data_invalidating_arg(target) else {
        return false;
    };
    let fragment_start = verifier_fragment_start_line(context.log, instruction.line);
    dynptr_stack_slot_for_call_argument(context.branch_states, instruction, fragment_start, arg_reg)
        == Some(origin.slot)
}

fn dynptr_data_invalidated_by_callback_write(
    context: &ProofSignalContext<'_>,
    after_line: usize,
    before_line: usize,
    origin: DynptrDataOrigin,
) -> bool {
    if after_line >= before_line {
        return false;
    }
    let fragment_start = verifier_fragment_start_line(context.log, before_line);
    context
        .branch_states
        .iter()
        .filter(|state| state.log_line > after_line)
        .filter(|state| state.log_line < before_line)
        .filter(|state| state.callback_kind == Some(CallbackKind::Sync))
        .filter(|state| state.from_pc.is_some())
        .any(|entry| {
            bpf_loop_callback_entry_stack_pointer(context, fragment_start, entry).is_some_and(
                |data_slot| stack_pointer_can_reach_dynptr_slot(data_slot, origin.slot),
            ) && callback_writes_dynptr_slot(
                context,
                fragment_start,
                entry,
                before_line,
                origin.slot,
            )
        })
}

fn bpf_loop_callback_entry_stack_pointer(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    entry: &VerifierInsn,
) -> Option<DynptrStackSlot> {
    let from_pc = entry.from_pc?;
    let call_instruction =
        instruction_site_before_line(context.log, from_pc, fragment_start, entry.log_line)?;
    if call_target_from_instruction_tail(call_instruction.tail) != Some("bpf_loop") {
        return None;
    }
    let call_slot = dynptr_stack_slot_for_call_argument(
        context.branch_states,
        call_instruction,
        fragment_start,
        3,
    )?;
    let entry_slot = callback_entry_stack_slot(entry, 2)?;
    (call_slot == entry_slot).then_some(entry_slot)
}

fn stack_pointer_can_reach_dynptr_slot(pointer: DynptrStackSlot, slot: DynptrStackSlot) -> bool {
    if pointer.frame != slot.frame {
        return false;
    }
    let Some(slot_range) = dynptr_stack_slot_range(slot) else {
        return false;
    };
    i16::try_from(pointer.offset)
        .ok()
        .is_some_and(|offset| slot_range.contains(offset))
}

fn callback_entry_stack_slot(entry: &VerifierInsn, reg: u8) -> Option<DynptrStackSlot> {
    let reg_state = entry.regs.get(&reg)?;
    if reg_state.reg_type != "fp" || reg_state_has_variable_offset(reg_state) {
        return None;
    }
    Some(DynptrStackSlot {
        frame: reg_state.source_frame.unwrap_or(entry.frame),
        offset: reg_state.offset?,
    })
}

fn callback_writes_dynptr_slot(
    context: &ProofSignalContext<'_>,
    fragment_start: usize,
    entry: &VerifierInsn,
    before_line: usize,
    slot: DynptrStackSlot,
) -> bool {
    let Some(slot_range) = dynptr_stack_slot_range(slot) else {
        return false;
    };
    instructions_in_line_range(context.log, entry.log_line.saturating_add(1), before_line)
        .filter(|instruction| memory_access_is_store(instruction.tail))
        .any(|instruction| {
            callback_instruction_matches_entry(
                context.branch_states,
                instruction,
                fragment_start,
                entry,
            ) && memory_store_overlaps_dynptr_slot(
                context.branch_states,
                instruction,
                fragment_start,
                slot,
                slot_range,
            )
        })
}

fn callback_instruction_matches_entry(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    entry: &VerifierInsn,
) -> bool {
    latest_verifier_state_before_instruction(states, instruction, fragment_start).is_some_and(
        |state| {
            state.log_line >= entry.log_line
                && state.frame == entry.frame
                && state.callback_kind == entry.callback_kind
        },
    )
}

fn memory_store_overlaps_dynptr_slot(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    slot: DynptrStackSlot,
    slot_range: StackByteRange,
) -> bool {
    let Some(base_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    let Some((base, frame)) = latest_reg_state_before_instruction_with_frame(
        states,
        instruction,
        fragment_start,
        base_reg,
    ) else {
        return false;
    };
    if frame != slot.frame || base.reg_type != "fp" || reg_state_has_variable_offset(base) {
        return false;
    }
    stack_memory_access_range(base, instruction.tail)
        .is_some_and(|access| access.overlaps(slot_range))
}

fn dynptr_stack_slot_range(slot: DynptrStackSlot) -> Option<StackByteRange> {
    stack_value_range(i16::try_from(slot.offset).ok()?, 16)
}
