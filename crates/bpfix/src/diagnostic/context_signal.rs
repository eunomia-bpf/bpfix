use bpfanalysis::verifier_log::{
    latest_reg_state_before, latest_reg_state_before_instruction,
    latest_reg_state_before_instruction_with_origin, memory_access_base_register,
    memory_access_is_load, memory_access_offset, memory_access_width, parse_u32_after,
    terminal_instruction_site, VerifierInsn, VerifierLogInstruction as TerminalInstruction,
};

use crate::family::ProofObligation;

use super::{
    latest_register_assignment, register_from_terminal_error, rejected_source,
    terminal_error_has_nearby_prior_line, terminal_fragment_start, ProofSignalContext,
};

pub(super) fn context_access_source_argument_mismatch(context: &ProofSignalContext<'_>) -> bool {
    bpf_prog_context_argument_mismatch(context)
        || trace_context_scalar_argument_dereference(context)
}

fn bpf_prog_context_argument_mismatch(context: &ProofSignalContext<'_>) -> bool {
    let terminal = context.terminal_error.to_ascii_lowercase();
    if !(terminal.contains("invalid bpf_context access")
        || terminal.contains("invalid ctx access")
        || terminal.contains("invalid access to context"))
    {
        return false;
    }
    if !terminal_error_has_nearby_prior_line(context.log, context.terminal_error, 3, |line| {
        line.contains("type PTR is not a struct")
    }) {
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

fn trace_context_scalar_argument_dereference(context: &ProofSignalContext<'_>) -> bool {
    if context.obligation != ProofObligation::PointerProvenance {
        return false;
    }
    if !active_context_section_is_tracepoint(context) {
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
    source_looks_like_trace_context_pointer_use(context, origin.pc, instruction.pc)
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

fn source_looks_like_trace_context_pointer_use<'a>(
    context: &ProofSignalContext<'a>,
    origin_pc: usize,
    rejected_pc: usize,
) -> bool {
    let origin_source = source_text_for_pc(context, origin_pc);
    let rejected_source = source_text_for_pc(context, rejected_pc)
        .or_else(|| rejected_source(context.events).map(|source| source.text.as_str()));
    [origin_source, rejected_source]
        .into_iter()
        .flatten()
        .any(trace_context_pointer_source_text)
}

fn source_text_for_pc<'a>(context: &ProofSignalContext<'a>, pc: usize) -> Option<&'a str> {
    context
        .source_events
        .iter()
        .filter(|event| event.pc.is_some_and(|event_pc| event_pc <= pc))
        .max_by_key(|event| event.pc)
        .map(|event| event.source.text.as_str())
}

fn trace_context_pointer_source_text(text: &str) -> bool {
    text.contains("PT_REGS_")
        || text.contains("ctx->envp")
        || text.contains("ctx->argv")
        || text.contains("ctx->filename")
}

fn active_context_section_is_tracepoint(context: &ProofSignalContext<'_>) -> bool {
    if !context.object_sections.is_empty() {
        return context
            .object_sections
            .iter()
            .any(|section| section_is_tracepoint(section));
    }
    active_libbpf_program_section(context).is_some_and(section_is_tracepoint)
}

fn section_is_tracepoint(section: &str) -> bool {
    let section = section.trim_start_matches('?');
    section.starts_with("tracepoint/")
        || section.starts_with("tp/")
        || section.starts_with("raw_tracepoint/")
        || section.starts_with("raw_tp/")
        || section == "raw_tp"
}

fn active_libbpf_program_section<'a>(context: &ProofSignalContext<'a>) -> Option<&'a str> {
    let before_line = terminal_error_line_in_log(context.full_log, context.terminal_error)?;
    let (program_name, window_start) = current_libbpf_program_scope(context.full_log, before_line)?;
    libbpf_section_for_program(context.full_log, window_start, before_line, program_name)
}

fn libbpf_section_for_program<'a>(
    log: &'a str,
    window_start: usize,
    before_line: usize,
    program_name: &str,
) -> Option<&'a str> {
    let lines = log.lines().collect::<Vec<_>>();
    let end = before_line.saturating_sub(1).min(lines.len());
    let start = window_start.saturating_sub(1).min(end);
    lines[start..end]
        .iter()
        .rev()
        .find_map(|line| libbpf_found_program_section(line, program_name))
}

fn libbpf_found_program_section<'a>(line: &'a str, program_name: &str) -> Option<&'a str> {
    let (_, tail) = line.split_once("libbpf: sec '")?;
    let (section, tail) = tail.split_once("': found program '")?;
    let (found_program, _) = tail.split_once('\'')?;
    (found_program == program_name && !section.is_empty()).then_some(section)
}

pub(super) fn context_field_unavailable(context: &ProofSignalContext<'_>) -> bool {
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
