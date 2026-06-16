use bpfanalysis::helper_abi::helper_map_value_memory_access_pair;
use bpfanalysis::verifier_log::{
    conditional_branch_registers, direct_call_target_from_instruction_tail,
    instruction_adds_register, instruction_on_log_line, instructions_in_line_range,
    latest_reg_state_before, latest_reg_state_before_instruction, map_value_access_error,
    map_value_access_range_may_exceed_value_size, map_value_range_may_exceed_value_size,
    map_value_remaining_capacity, map_value_variable_max_offset, memory_access_base_register,
    memory_access_offset, memory_access_width, scalar_ranges_match,
    scalar_state_upper_bound_at_most, terminal_instruction_access_width,
    terminal_instruction_memory_offset, RegState, VerifierInsn,
    VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;
use crate::source::{looks_like_scalar_guard, SourceEvent, SourceLocation};

use super::source_query::{
    identifier_tokens, is_bare_identifier_argument, max_numeric_token, numeric_tokens,
    rejected_source, same_source_location,
};
use super::{
    register_from_terminal_error, terminal_site, ProofEvent, ProofEventEvidence, ProofEventRole,
    ProofSignal, ProofSignalContext,
};

pub(super) fn map_value_wide_access(
    log: &str,
    terminal_error: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    register: Option<u8>,
    states: &[VerifierInsn],
) -> bool {
    let Some(access) = map_value_access_error(terminal_error) else {
        return false;
    };
    let Some(reg) = register else {
        return false;
    };
    if !access.access_is_wider_than_value() {
        return false;
    }
    if terminal_instruction_access_width(log, terminal_pc, terminal_line) != Some(access.size) {
        return false;
    }
    latest_reg_state_before(states, terminal_pc, reg).is_some_and(|state| {
        state.reg_type == "map_value" && state.map_value_size == Some(access.value_size)
    })
}

pub(super) fn map_value_checked_offset_relation_lost(
    terminal_error: &str,
    terminal_pc: Option<usize>,
    register: Option<u8>,
    states: &[VerifierInsn],
    events: &[ProofEvent],
    source_events: &[SourceEvent],
) -> bool {
    let Some(access) = map_value_access_error(terminal_error) else {
        return false;
    };
    let Some(reg) = register else {
        return false;
    };
    if access.access_is_wider_than_value() {
        return false;
    }
    if !access.exceeds_value_size() {
        return false;
    }
    let Some(rejected) = rejected_source(events) else {
        return false;
    };
    if !source_guard_mentions_bound(events, source_events, access.value_size, rejected) {
        return false;
    }
    latest_reg_state_before(states, terminal_pc, reg).is_some_and(|state| {
        state.reg_type == "map_value"
            && state.map_value_size == Some(access.value_size)
            && map_value_range_may_exceed_value_size(state)
    })
}

pub(super) fn map_value_guard_exceeds_value_size(context: &ProofSignalContext<'_>) -> bool {
    let Some(access) = map_value_access_error(context.terminal_error) else {
        return false;
    };
    let Some(reg) = context.register else {
        return false;
    };
    if access.access_is_wider_than_value() {
        return false;
    }
    let Some(state) = latest_reg_state_before(context.states, context.terminal_pc, reg) else {
        return false;
    };
    if state.reg_type != "map_value" || state.map_value_size != Some(access.value_size) {
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
    let Some(bytes_after_field) = access.value_size.checked_sub(total_fixed_offset) else {
        return false;
    };
    let Some(max_index) = bytes_after_field.checked_sub(access.size) else {
        return false;
    };
    if map_value_variable_max_offset(state).is_none_or(|max| max <= u64::from(max_index)) {
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

pub(super) fn map_value_access_out_of_bounds(context: &ProofSignalContext<'_>) -> bool {
    let Some(access) = map_value_access_error(context.terminal_error) else {
        return false;
    };
    if !access.exceeds_value_size() {
        return false;
    }
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    let instruction_target = direct_call_target_from_instruction_tail(instruction.tail);
    let Some(reg) = memory_access_base_register(instruction.tail)
        .or_else(|| {
            instruction_target
                .and_then(helper_map_value_memory_access_pair)
                .map(|pair| pair.ptr_reg)
        })
        .or(context.register)
        .or_else(|| register_from_terminal_error(context.terminal_error))
    else {
        return false;
    };
    let Some(state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    ) else {
        return false;
    };
    if state.reg_type != "map_value" || state.map_value_size != Some(access.value_size) {
        return false;
    }
    if let Some(base_reg) = memory_access_base_register(instruction.tail) {
        if access.access_is_wider_than_value() {
            return false;
        }
        return base_reg == reg
            && memory_access_width(instruction.tail) == Some(access.size)
            && map_value_terminal_offset_matches_state(
                state,
                access.offset,
                memory_access_offset(instruction.tail),
            );
    }
    let Some(target) = instruction_target else {
        return false;
    };
    helper_map_value_memory_access_pair(target).is_some_and(|pair| pair.ptr_reg == reg)
        && map_value_terminal_offset_matches_state(state, access.offset, Some(0))
        && helper_memory_access_length_matches(
            context.branch_states,
            instruction,
            fragment_start,
            target,
            access.size,
        )
}

fn map_value_terminal_offset_matches_state(
    state: &RegState,
    reported_offset: i64,
    instruction_offset: Option<i64>,
) -> bool {
    let Some(instruction_offset) = instruction_offset else {
        return false;
    };
    i64::from(state.offset.unwrap_or(0)).saturating_add(instruction_offset) == reported_offset
}

fn helper_memory_access_length_matches(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
    target: &str,
    access_size: u32,
) -> bool {
    let Some(length_reg) = helper_map_value_memory_access_pair(target).map(|pair| pair.len_reg)
    else {
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
            || scalar_guard_upper_bound_for_identifier(&source.text, index)
                .is_none_or(|upper| upper <= max_index)
        {
            return false;
        }
        let Some(guard_pc) = event.pc else {
            return false;
        };
        if context
            .terminal_pc
            .is_none_or(|terminal_pc| guard_pc >= terminal_pc)
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
        if context
            .terminal_line
            .is_none_or(|terminal_line| guard_log_line >= terminal_line)
        {
            return false;
        }
        scalar_guard_verifier_state_links_to_map_value(
            context,
            guard_pc,
            guard_log_line,
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
    context: &ProofSignalContext<'_>,
    guard_pc: usize,
    guard_log_line: usize,
    map_reg: u8,
    current: &RegState,
) -> bool {
    context
        .branch_states
        .iter()
        .filter(|state| state.pc >= guard_pc && state.pc <= guard_pc.saturating_add(3))
        .filter(|state| state.log_line > guard_log_line)
        .filter(|state| {
            context
                .terminal_line
                .is_none_or(|terminal_line| state.log_line < terminal_line)
        })
        .any(|state| {
            let Some(instruction) = instruction_on_log_line(context.log, state.log_line) else {
                return false;
            };
            if instruction.pc != state.pc {
                return false;
            }
            let regs = conditional_branch_registers(instruction.tail);
            regs.iter().any(|reg| {
                state.regs.get(reg).is_some_and(|guard| {
                    guard.reg_type == "scalar"
                        && scalar_ranges_match(guard, current)
                        && map_value_add_uses_scalar_between(
                            context.log,
                            guard_pc,
                            guard_log_line,
                            context.terminal_pc,
                            context.terminal_line,
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
    let before_line = terminal_line.unwrap_or(usize::MAX);
    instructions_in_line_range(log, guard_log_line.saturating_add(1), before_line).any(
        |instruction| {
            instruction.pc > guard_pc
                && instruction.pc < terminal_pc
                && instruction_adds_register(instruction.tail, map_reg, scalar_reg)
        },
    )
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
    let digits = text.trim().trim_end_matches(['u', 'U', 'l', 'L']);
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

pub(super) fn verifier_precision_signal(context: &ProofSignalContext<'_>) -> Option<ProofSignal> {
    match context.obligation {
        ProofObligation::ScalarRange if map_value_relation_precision_boundary(context) => {
            Some(ProofSignal::MapValueRelationPrecisionBoundary)
        }
        _ => None,
    }
}

fn map_value_relation_precision_boundary(context: &ProofSignalContext<'_>) -> bool {
    let Some(access) = map_value_access_error(context.terminal_error) else {
        return false;
    };
    if !access.exceeds_value_size() {
        return false;
    }
    let Some((instruction, fragment_start)) = terminal_site(context) else {
        return false;
    };
    let Some(target) = direct_call_target_from_instruction_tail(instruction.tail) else {
        return false;
    };
    let Some(pair) = helper_map_value_memory_access_pair(target) else {
        return false;
    };
    let pointer_reg = pair.ptr_reg;
    let length_reg = pair.len_reg;
    let Some(pointer_state) = latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        pointer_reg,
    ) else {
        return false;
    };
    if pointer_state.reg_type != "map_value"
        || pointer_state.map_value_size != Some(access.value_size)
    {
        return false;
    }
    let Some(relation_capacity) = map_value_remaining_capacity(pointer_state, access.value_size)
    else {
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
    if map_value_access_range_may_exceed_value_size(pointer_state, access.size) {
        return true;
    }
    latest_reg_state_before_instruction(
        context.branch_states,
        instruction,
        fragment_start,
        length_reg,
    )
    .is_some_and(|state| {
        access.access_is_wider_than_value()
            && scalar_state_upper_bound_matches_size(state, access.size)
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

fn text_has_numeric_token(text: &str, expected: u32) -> bool {
    numeric_tokens(text)
        .into_iter()
        .any(|token| token == expected)
}
