use super::{
    instruction_frame, is_verifier_error_line, parse_signed_decimal, verifier_fragment_start_line,
    VerifierInsn,
};

/// Parses the verifier-log PC prefix from `<pc>:` lines.
///
/// This intentionally accepts both opcode rows and state-only rows such as
/// `17: R1=ctx()`. Use [`parse_instruction_line`] when the caller needs an
/// actual opcode tail.
pub fn parse_instruction_pc(line: &str) -> Option<usize> {
    parse_instruction_prefix(line).map(|(pc, _)| pc)
}

/// Parses a verifier opcode row and returns its PC plus opcode tail.
pub fn parse_instruction_line(line: &str) -> Option<(usize, &str)> {
    let (pc, tail) = parse_instruction_prefix(line)?;
    Some((pc, instruction_opcode_tail(tail.trim_start())?))
}

/// Extracts the token after the first `call` word in an instruction tail.
///
/// This is a loose helper for already-filtered verifier rows. Use
/// [`direct_call_target_from_instruction_tail`] when the caller needs to prove
/// that the tail is exactly a direct BPF call instruction.
pub fn call_target_from_instruction_tail(line: &str) -> Option<&str> {
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

/// Extracts the target from a strict `(85) call <target>` instruction tail.
pub fn direct_call_target_from_instruction_tail(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "(85)" || tokens.next()? != "call" {
        return None;
    }
    let call = tokens.next()?;
    call.split_once('#')
        .map(|(target, _)| target)
        .or(Some(call))
}

/// Scans textual operands for `rN` register mentions.
///
/// This is intentionally a lightweight verifier-log scanner, not a complete
/// BPF assembly lexer. It does not include `wN` write aliases.
pub fn loose_register_operands(text: &str) -> Vec<u8> {
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

pub fn register_token(token: &str) -> Option<u8> {
    parse_register_token(token, false)
}

pub fn register_write_token(token: &str) -> Option<u8> {
    parse_register_token(token, true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierLogInstruction<'a> {
    pub pc: usize,
    pub line: usize,
    pub tail: &'a str,
}

pub fn instruction_on_log_line(
    log: &str,
    line_number: usize,
) -> Option<VerifierLogInstruction<'_>> {
    let line = log.lines().nth(line_number.checked_sub(1)?)?;
    let (pc, tail) = parse_instruction_line(line.trim())?;
    Some(VerifierLogInstruction {
        pc,
        line: line_number,
        tail,
    })
}

pub fn call_target_on_log_line(log: &str, line_number: usize) -> Option<&str> {
    instruction_on_log_line(log, line_number)
        .and_then(|instruction| call_target_from_instruction_tail(instruction.tail))
}

pub fn terminal_instruction_site(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<VerifierLogInstruction<'_>> {
    let pc = terminal_pc?;
    let line_count = log.lines().count();
    let before_line = terminal_line
        .unwrap_or_else(|| line_count.saturating_add(1))
        .min(line_count.saturating_add(1));
    let end = before_line.saturating_sub(1).min(line_count);
    let fragment_start = terminal_line
        .map(|line| verifier_fragment_start_line(log, line))
        .unwrap_or(1)
        .min(end.saturating_add(1));
    instruction_site_before_line(log, pc, fragment_start, before_line)
}

pub fn terminal_or_nearest_call_instruction_site<'a>(
    log: &'a str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    expected_target: Option<&'a str>,
) -> Option<VerifierLogInstruction<'a>> {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .or_else(|| nearest_call_instruction_before(log, terminal_line?, expected_target))
}

fn nearest_call_instruction_before<'a>(
    log: &'a str,
    terminal_line: usize,
    expected_target: Option<&'a str>,
) -> Option<VerifierLogInstruction<'a>> {
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
        return Some(VerifierLogInstruction {
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

pub fn instruction_site_before_line(
    log: &str,
    pc: usize,
    fragment_start_line: usize,
    before_line: usize,
) -> Option<VerifierLogInstruction<'_>> {
    instructions_in_line_range(log, fragment_start_line, before_line)
        .filter(|instruction| instruction.pc == pc)
        .last()
}

pub fn instructions_in_line_range(
    log: &str,
    start_line: usize,
    before_line: usize,
) -> impl Iterator<Item = VerifierLogInstruction<'_>> {
    log.lines()
        .enumerate()
        .skip(start_line.saturating_sub(1))
        .take(before_line.saturating_sub(start_line))
        .filter_map(|(idx, line)| {
            let line_number = idx + 1;
            let (line_pc, tail) = parse_instruction_line(line.trim())?;
            Some(VerifierLogInstruction {
                pc: line_pc,
                line: line_number,
                tail,
            })
        })
}

pub fn active_validation_start(log: &str, start_line: usize, before_line: usize) -> Option<usize> {
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

pub fn validation_seen(log: &str, start_line: usize, before_line: usize) -> bool {
    log.lines()
        .skip(start_line.saturating_sub(1))
        .take(before_line.saturating_sub(start_line))
        .any(|line| validating_function_name(line.trim()).is_some())
}

fn validating_function_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("Validating ")?;
    let (name, _) = rest.split_once("() func#")?;
    (!name.is_empty()).then_some(name)
}

fn validation_success_line(line: &str) -> bool {
    line.starts_with("Func#") && line.contains(" is safe for any args")
}

pub fn terminal_instruction_access_width(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<u32> {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .and_then(|instruction| memory_access_width(instruction.tail))
}

pub fn terminal_instruction_memory_offset(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<i64> {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .and_then(|instruction| memory_access_offset(instruction.tail))
}

pub fn terminal_instruction_contains(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
    needle: &str,
) -> bool {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .is_some_and(|instruction| instruction.tail.contains(needle))
}

pub fn terminal_call_target(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<&str> {
    terminal_instruction_site(log, terminal_pc, terminal_line)
        .and_then(|instruction| call_target_from_instruction_tail(instruction.tail))
}

pub fn memory_access_width(line_after_pc: &str) -> Option<u32> {
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

pub fn memory_access_is_load(line_after_pc: &str) -> bool {
    line_after_pc.contains("= *(")
}

pub fn memory_access_is_store(line_after_pc: &str) -> bool {
    !memory_access_is_load(line_after_pc)
        && line_after_pc.contains("*)(")
        && line_after_pc.contains(" = ")
}

pub fn instruction_opcode_body(line_after_pc: &str) -> &str {
    line_after_pc
        .split_once(';')
        .map_or(line_after_pc, |(body, _)| body)
        .trim()
}

pub fn instruction_destination_register(instruction_tail: &str) -> Option<u8> {
    let (_, rest) = instruction_tail.split_once(')')?;
    let lhs = rest.trim_start().split_once(" = ")?.0.trim();
    register_write_token(lhs)
}

pub fn instruction_assigns_register(instruction_tail: &str, reg: u8) -> bool {
    if reg == 0 && call_target_from_instruction_tail(instruction_tail).is_some() {
        return true;
    }
    let Some((_, rest)) = instruction_tail.split_once(')') else {
        return false;
    };
    let body = rest.split_once(';').map_or(rest, |(body, _)| body).trim();
    body.starts_with(&format!("r{reg} ")) || body.starts_with(&format!("w{reg} "))
}

pub fn latest_register_assignment<'a>(
    states: &[VerifierInsn],
    log: &'a str,
    fragment_start_line: usize,
    before_line: usize,
    reg: u8,
    frame: usize,
) -> Option<VerifierLogInstruction<'a>> {
    instructions_in_line_range(log, fragment_start_line, before_line)
        .filter(|instruction| {
            instruction_assigns_register(instruction.tail, reg)
                && instruction_frame(states, *instruction, fragment_start_line)
                    .is_none_or(|assigned_frame| assigned_frame == frame)
        })
        .last()
}

pub fn register_assigned_between(
    states: &[VerifierInsn],
    log: &str,
    reg: u8,
    frame: usize,
    fragment_start_line: usize,
    after_line: usize,
    before_line: usize,
) -> bool {
    instructions_in_line_range(log, after_line.saturating_add(1), before_line)
        .filter(|instruction| instruction_assigns_register(instruction.tail, reg))
        .any(|instruction| {
            instruction_frame(states, instruction, fragment_start_line)
                .is_none_or(|assigned_frame| assigned_frame == frame)
        })
}

pub fn instruction_writes_register(instruction_tail: &str, reg: u8) -> bool {
    let mut tokens = instruction_tail.split_whitespace();
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

pub fn register_written_between(log: &str, after_line: usize, before_line: usize, reg: u8) -> bool {
    instructions_in_line_range(log, after_line.saturating_add(1), before_line)
        .any(|instruction| instruction_writes_register(instruction.tail, reg))
}

pub fn instruction_is_bpf_exit(instruction_tail: &str) -> bool {
    let mut tokens = instruction_tail.split_whitespace();
    tokens.next() == Some("(95)") && tokens.next() == Some("exit")
}

pub fn instruction_register_copy_source(instruction_tail: &str, destination: u8) -> Option<u8> {
    if instruction_destination_register(instruction_tail) != Some(destination) {
        return None;
    }
    let rhs = instruction_assignment_rhs(instruction_tail)?;
    register_token(rhs.trim())
}

pub fn instruction_single_register_rhs_source(
    instruction_tail: &str,
    destination: u8,
) -> Option<u8> {
    if instruction_destination_register(instruction_tail) != Some(destination) {
        return None;
    }
    let rhs = instruction_assignment_rhs(instruction_tail)?;
    if !rhs.starts_with('r') && !rhs.starts_with('w') {
        return None;
    }
    let regs = loose_register_operands(rhs);
    (regs.len() == 1).then_some(regs[0])
}

fn instruction_assignment_rhs(instruction_tail: &str) -> Option<&str> {
    let (_, rest) = instruction_tail.split_once(')')?;
    let (_, rhs) = rest
        .split_once(';')
        .map_or(rest, |(body, _)| body)
        .trim()
        .split_once(" = ")?;
    Some(rhs)
}

pub fn instruction_uses_register(instruction_tail: &str, reg: u8) -> bool {
    let needle = format!("r{reg}");
    instruction_tail
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token == needle)
}

pub fn instruction_reads_register(opcode_tail: &str, reg: u8) -> bool {
    if let Some(operand) = memory_access_operand(opcode_tail) {
        return loose_register_operands(operand).contains(&reg);
    }
    if opcode_tail.split_once(" = ").is_some() {
        return false;
    }
    loose_register_operands(opcode_tail).contains(&reg)
}

pub fn conditional_branch_registers(instruction_tail: &str) -> Vec<u8> {
    let Some(condition) = instruction_tail
        .split_once(" if ")
        .map(|(_, condition)| condition)
        .or_else(|| instruction_tail.strip_prefix("if "))
    else {
        return Vec::new();
    };
    let condition = condition.split(" goto ").next().unwrap_or(condition);
    loose_register_operands(condition)
}

pub fn instruction_adds_register(instruction_tail: &str, destination: u8, source: u8) -> bool {
    let mut tokens = instruction_tail.split_whitespace();
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

pub fn memory_access_is_atomic(line_after_pc: &str) -> bool {
    let body = instruction_opcode_body(line_after_pc);
    (body.contains("atomic") && body.contains("*)(")) || body.contains("lock *(")
}

pub fn atomic_memory_access_width(line_after_pc: &str) -> Option<u32> {
    let body = instruction_opcode_body(line_after_pc);
    if !memory_access_is_atomic(body) {
        return None;
    }
    let marker = "(u";
    let bytes = body.as_bytes();
    let mut search_start = 0usize;
    while let Some(relative) = body[search_start..].find(marker) {
        let start = search_start + relative + marker.len();
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > start && body.get(end..end + 4) == Some(" *)(") {
            return body[start..end]
                .parse::<u32>()
                .ok()
                .and_then(|bits| bits.checked_div(8));
        }
        search_start = search_start + relative + marker.len();
    }
    None
}

pub fn memory_access_offset(line_after_pc: &str) -> Option<i64> {
    let operand = memory_access_operand(line_after_pc)?;
    if let Some((_, offset)) = operand.rsplit_once('+') {
        return parse_signed_decimal(offset);
    }
    if let Some((_, offset)) = operand.rsplit_once('-') {
        return parse_signed_decimal(offset).map(|value| -value);
    }
    loose_register_operands(operand).first().map(|_| 0)
}

pub fn memory_access_base_register(line_after_pc: &str) -> Option<u8> {
    loose_register_operands(memory_access_operand(line_after_pc)?)
        .first()
        .copied()
}

pub fn memory_access_operand(line_after_pc: &str) -> Option<&str> {
    let (_, after_marker) = line_after_pc.split_once("*)(")?;
    Some(after_marker.split_once(')')?.0.trim())
}

fn parse_instruction_prefix(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start();
    let digits_len = trimmed
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits_len == 0 || trimmed.as_bytes().get(digits_len) != Some(&b':') {
        return None;
    }
    Some((
        trimmed[..digits_len].parse().ok()?,
        trimmed[digits_len + 1..].trim_start(),
    ))
}

fn instruction_opcode_tail(tail: &str) -> Option<&str> {
    if looks_like_opcode_tail(tail) {
        return Some(tail);
    }
    let mask_len = tail.find(char::is_whitespace)?;
    tail[..mask_len]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        .then(|| tail[mask_len..].trim_start())
        .filter(|rest| looks_like_opcode_tail(rest))
}

fn looks_like_opcode_tail(tail: &str) -> bool {
    let bytes = tail.as_bytes();
    bytes.len() >= 4
        && bytes[0] == b'('
        && bytes[1..3].iter().all(u8::is_ascii_hexdigit)
        && bytes[3] == b')'
}

fn parse_register_token(token: &str, allow_w: bool) -> Option<u8> {
    let token = token.trim_end_matches([',', ';']);
    let digits = token
        .strip_prefix('r')
        .or_else(|| allow_w.then(|| token.strip_prefix('w')).flatten())?;
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}
