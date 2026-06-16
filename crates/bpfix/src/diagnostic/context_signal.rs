use bpfanalysis::libbpf_log::{
    active_libbpf_program_section, core_relocation_struct_for_active_program,
};
use bpfanalysis::verifier_log::{
    latest_reg_state_before, latest_reg_state_before_instruction,
    latest_reg_state_before_instruction_with_origin, memory_access_base_register,
    memory_access_is_load, memory_access_offset, memory_access_width, parse_u32_after,
    terminal_instruction_site, VerifierInsn, VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;

use super::source_query::rejected_source;
use super::{
    latest_register_assignment, register_from_terminal_error, terminal_error_has_nearby_prior_line,
    terminal_fragment_start, ProofSignalContext,
};

pub(super) fn bpf_prog_context_argument_mismatch(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid bpf_context access")
        || terminal.contains("invalid ctx access")
        || terminal.contains("invalid access to context"))
    {
        return false;
    }
    if !terminal_error_has_nearby_prior_line(
        context.log,
        context.terminal_error,
        context.terminal_line,
        3,
        |line| line.contains("type PTR is not a struct"),
    ) {
        return false;
    }
    let Some(rejected) = rejected_source(context.events) else {
        return false;
    };
    if !rejected.text.contains("BPF_PROG(") {
        return false;
    }
    latest_reg_state_before(context.states, context.terminal_pc, 1)
        .is_some_and(|state| state.reg_type == "ctx")
}

pub(super) fn trace_context_scalar_argument_dereference(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PointerProvenance {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid mem access 'scalar'")
        || terminal.contains("invalid mem access 'inv'"))
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(reg) = context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
    else {
        return false;
    };
    if memory_access_base_register(instruction.tail) != Some(reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some((state, _, frame)) = latest_reg_state_before_instruction_with_origin(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    ) else {
        return false;
    };
    if state.reg_type != "scalar" {
        return false;
    }
    let Some(origin) = latest_register_assignment(
        context.states,
        context.log,
        fragment_start,
        instruction.line,
        reg,
        frame,
    ) else {
        return false;
    };
    if !context_scalar_loaded_from_ctx(context.states, origin, fragment_start) {
        return false;
    }
    let source_use = trace_context_pointer_source_use(
        context,
        origin.pc,
        instruction.pc,
        fragment_start,
        instruction.line,
    );
    source_use.direct_ctx_field
        || (source_use.typed_pointer_use && active_context_section_is_tracepoint(context))
}

fn context_scalar_loaded_from_ctx(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> bool {
    if !memory_access_is_load(instruction.tail) {
        return false;
    }
    let Some(ctx_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    latest_reg_state_before_instruction(states, instruction, fragment_start, ctx_reg)
        .is_some_and(|state| state.reg_type == "ctx")
}

#[derive(Clone, Copy, Default)]
struct TraceContextPointerSourceUse {
    typed_pointer_use: bool,
    direct_ctx_field: bool,
}

fn trace_context_pointer_source_use<'a>(
    context: &ProofSignalContext<'a>,
    origin_pc: usize,
    rejected_pc: usize,
    fragment_start: usize,
    before_line: usize,
) -> TraceContextPointerSourceUse {
    let origin_source = source_text_for_pc(context, origin_pc, fragment_start, before_line);
    let rejected_source = source_text_for_pc(context, rejected_pc, fragment_start, before_line)
        .or_else(|| rejected_source_text_in_fragment(context, fragment_start, before_line));
    [origin_source, rejected_source].into_iter().flatten().fold(
        TraceContextPointerSourceUse::default(),
        |use_shape, source| TraceContextPointerSourceUse {
            typed_pointer_use: use_shape.typed_pointer_use
                || trace_context_typed_pointer_source_text(source),
            direct_ctx_field: use_shape.direct_ctx_field || trace_context_direct_ctx_field(source),
        },
    )
}

fn trace_context_typed_pointer_source_text(text: &str) -> bool {
    text.contains("PT_REGS_") || trace_context_direct_ctx_field(text)
}

fn trace_context_direct_ctx_field(text: &str) -> bool {
    ["ctx->args", "ctx->envp", "ctx->argv", "ctx->filename"]
        .into_iter()
        .any(|field| text.contains(field))
}

fn source_text_for_pc<'a>(
    context: &ProofSignalContext<'a>,
    pc: usize,
    fragment_start: usize,
    before_line: usize,
) -> Option<&'a str> {
    context
        .source_events
        .iter()
        .filter(|event| event.log_line >= fragment_start)
        .filter(|event| event.log_line < before_line)
        .filter(|event| event.pc.is_some_and(|event_pc| event_pc <= pc))
        .max_by_key(|event| (event.pc, event.log_line))
        .map(|event| event.source.text.as_str())
}

fn rejected_source_text_in_fragment<'a>(
    context: &ProofSignalContext<'a>,
    fragment_start: usize,
    before_line: usize,
) -> Option<&'a str> {
    let rejected = rejected_source(context.events)?;
    context
        .source_events
        .iter()
        .filter(|event| event.log_line >= fragment_start)
        .filter(|event| event.log_line < before_line)
        .find(|event| event.source == *rejected)
        .map(|event| event.source.text.as_str())
}

fn active_context_section_is_tracepoint(context: &ProofSignalContext<'_>) -> bool {
    if !context.object_sections.is_empty() {
        return context
            .object_sections
            .iter()
            .any(|section| section_is_tracepoint(section));
    }
    terminal_error_line_in_log(context.full_log, context.terminal_error)
        .and_then(|before_line| active_libbpf_program_section(context.full_log, before_line))
        .is_some_and(section_is_tracepoint)
}

fn section_is_tracepoint(section: &str) -> bool {
    let section = section.trim_start_matches('?');
    section.starts_with("tracepoint/")
        || section.starts_with("tp/")
        || section.starts_with("raw_tracepoint/")
        || section.starts_with("raw_tp/")
        || section == "raw_tp"
}

pub(super) fn context_field_unavailable(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid bpf_context access")
        || terminal.contains("invalid ctx access")
        || terminal.contains("invalid access to context"))
    {
        return false;
    }
    if terminal_error_has_nearby_prior_line(
        context.log,
        context.terminal_error,
        context.terminal_line,
        3,
        |line| line.contains("type PTR is not a struct"),
    ) {
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
    let fragment_start = terminal_fragment_start(context, instruction);
    latest_reg_state_before_instruction(context.states, instruction, fragment_start, base_reg)
        .is_some_and(|state| state.reg_type == "ctx")
}

pub(super) fn packet_context_field_access_in_unsupported_program(
    context: &ProofSignalContext<'_>,
) -> bool {
    if context.obligation != ProofObligation::PointerProvenance
        || !active_object_section_is_skb_tracepoint(context.object_sections)
    {
        return false;
    }
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid mem access 'scalar'")
        || terminal.contains("invalid mem access 'inv'"))
    {
        return false;
    }
    let Some(instruction) =
        terminal_instruction_site(context.log, context.terminal_pc, context.terminal_line)
    else {
        return false;
    };
    let Some(reg) = context
        .register
        .or_else(|| register_from_terminal_error(context.terminal_error))
    else {
        return false;
    };
    if memory_access_base_register(instruction.tail) != Some(reg) {
        return false;
    }
    let fragment_start = terminal_fragment_start(context, instruction);
    let Some((state, _, frame)) = latest_reg_state_before_instruction_with_origin(
        context.branch_states,
        instruction,
        fragment_start,
        reg,
    ) else {
        return false;
    };
    if state.reg_type != "scalar" {
        return false;
    }
    let Some(origin) = latest_register_assignment(
        context.states,
        context.log,
        fragment_start,
        instruction.line,
        reg,
        frame,
    ) else {
        return false;
    };
    packet_context_field_loaded_from_ctx(context.states, origin, fragment_start)
}

pub(super) fn kernel_object_field_access_mismatch(context: &ProofSignalContext<'_>) -> bool {
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
    let fragment_start = terminal_fragment_start(context, instruction);
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
    core_relocation_struct_for_active_program(
        context.full_log,
        before_line,
        instruction.pc,
        access_offset,
    )
    .is_some_and(|relocated_struct| !kernel_struct_names_match(relocated_struct, reported_struct))
}

pub(super) fn active_object_section_is_skb_tracepoint(sections: &[String]) -> bool {
    let [section] = sections else {
        return false;
    };
    let section = section.trim_start_matches('?');
    section.starts_with("tracepoint/skb/") || section.starts_with("tp/skb/")
}

fn packet_context_field_loaded_from_ctx(
    states: &[VerifierInsn],
    instruction: TerminalInstruction<'_>,
    fragment_start: usize,
) -> bool {
    if !memory_access_is_load(instruction.tail) {
        return false;
    }
    if !memory_access_offset(instruction.tail).is_some_and(is_skb_packet_pointer_field_offset) {
        return false;
    }
    let Some(ctx_reg) = memory_access_base_register(instruction.tail) else {
        return false;
    };
    latest_reg_state_before_instruction(states, instruction, fragment_start, ctx_reg)
        .is_some_and(|state| state.reg_type == "ctx")
}

fn is_skb_packet_pointer_field_offset(offset: i64) -> bool {
    matches!(offset, 76 | 80)
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
