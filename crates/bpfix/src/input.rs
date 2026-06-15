use std::path::Path;

use anyhow::{Context, Result};

use crate::source::{parse_instruction_pc, parse_source_comment};

const TERMINAL_ERROR_MARKERS: &[&str] = &[
    "bpf program is too large",
    "combined stack size",
    "invalid ",
    "unbounded",
    "out of bounds",
    "outside of",
    "expected ",
    "expected=",
    "possibly null pointer passed to",
    "misaligned",
    "missing btf",
    "unknown opcode",
    "unknown func",
    "arg#",
    "unreleased reference",
    "reference has not",
    "unacquired reference",
    "helper call is not allowed",
    "helper access to the packet is not allowed",
    "cannot use helper",
    "calling kernel function",
    "jit does not support",
    "cannot ",
    "permission denied",
    "does not allow writes to packet data",
    "too many states",
    "processed 1000001",
    "loop is not bounded",
    "infinite loop detected",
    "back-edge",
    "same insn cannot be used with different pointers",
    "pointer arithmetic",
    "bitwise operator",
    "should have been in",
    "cannot restore irq",
    "rcu",
    "lock",
    "kfunc",
    "trusted",
    "iter",
    "min value is negative",
    "min value is outside",
    "dereference of modified ctx ptr",
    "makes pkt pointer",
    "type=",
    "!read_ok",
    "only read from",
    "access beyond struct",
    "has no valid kptr",
    "must be a known constant",
    "dynptr",
];

#[derive(Clone, Debug)]
pub(crate) struct LoadedInput {
    pub(crate) log: String,
    pub(crate) input_kind: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct TerminalError {
    pub(crate) line: usize,
    pub(crate) message: String,
    pub(crate) pc: Option<usize>,
    pub(crate) call_target: Option<String>,
    pub(crate) source_path: Option<String>,
    pub(crate) source_line: Option<usize>,
    pub(crate) source_text: Option<String>,
}

pub(crate) fn load_input(path: Option<&Path>) -> Result<LoadedInput> {
    let raw = match path {
        None => read_stdin()?,
        Some(path) if path == Path::new("-") => read_stdin()?,
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
    };
    let (log, input_kind) = normalize_verifier_log(raw, "verifier-log");
    Ok(LoadedInput { log, input_kind })
}

fn read_stdin() -> Result<String> {
    use std::io::Read;
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("failed to read verifier log from stdin")?;
    Ok(raw)
}

fn normalize_verifier_log(raw: String, base_kind: &'static str) -> (String, &'static str) {
    let normalized = normalize_log_wrappers(&raw);
    match extract_verifier_log_region(&normalized) {
        Some(region) => (region, "verifier-log-region"),
        None => (normalized, base_kind),
    }
}

fn normalize_log_wrappers(raw: &str) -> String {
    let mut normalized = raw
        .lines()
        .filter_map(normalize_log_line)
        .collect::<Vec<_>>()
        .join("\n");
    if !normalized.is_empty() && raw.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

fn normalize_log_line(line: &str) -> Option<String> {
    let stripped = strip_ansi_escape_sequences(line);
    let line = strip_ci_timestamp_prefix(stripped.trim_end_matches('\r')).trim_start();
    if is_ci_control_line(line) {
        None
    } else {
        Some(line.to_string())
    }
}

fn strip_ansi_escape_sequences(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for code in chars.by_ref() {
                if ('@'..='~').contains(&code) {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn strip_ci_timestamp_prefix(mut line: &str) -> &str {
    loop {
        let trimmed = line.trim_start();
        if let Some(rest) = strip_bracketed_timestamp(trimmed) {
            line = rest;
            continue;
        }
        let Some((token, rest)) = trimmed.split_once(char::is_whitespace) else {
            return trimmed;
        };
        if looks_like_iso8601_timestamp(token) {
            line = rest;
            continue;
        }
        return trimmed;
    }
}

fn strip_bracketed_timestamp(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('[')?;
    let close = rest.find(']')?;
    let timestamp = &rest[..close];
    if !looks_like_iso8601_timestamp(timestamp) {
        return None;
    }
    Some(rest[close + 1..].trim_start())
}

fn looks_like_iso8601_timestamp(token: &str) -> bool {
    let Some(prefix) = token.get(..19) else {
        return false;
    };
    let bytes = prefix.as_bytes();
    bytes.len() == 19
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && matches!(bytes[10], b'T' | b't' | b' ')
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[13] == b':'
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[16] == b':'
        && bytes[17..19].iter().all(u8::is_ascii_digit)
}

fn is_ci_control_line(line: &str) -> bool {
    line.starts_with("::group::")
        || line.starts_with("::endgroup::")
        || line.starts_with("##[group]")
        || line.starts_with("##[endgroup]")
}

fn extract_verifier_log_region(raw: &str) -> Option<String> {
    let lines = raw.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }

    let mut marked_regions = Vec::new();
    let mut search_from = 0;
    while let Some(begin_offset) = lines[search_from..]
        .iter()
        .position(|line| line.contains("-- BEGIN PROG LOAD LOG --"))
    {
        let begin = search_from + begin_offset;
        let end = lines
            .iter()
            .enumerate()
            .skip(begin + 1)
            .find_map(|(idx, line)| line.contains("-- END PROG LOAD LOG --").then_some(idx))
            .unwrap_or(lines.len());
        if begin + 1 < end {
            marked_regions.push((begin + 1, end));
        }
        if end >= lines.len() {
            break;
        }
        search_from = end + 1;
    }
    if let Some((start, end)) = marked_regions
        .iter()
        .rev()
        .copied()
        .find(|(start, end)| {
            lines[*start..*end]
                .iter()
                .any(|line| is_verifier_error_line(line.trim()))
        })
        .or_else(|| marked_regions.last().copied())
    {
        return Some(join_lines(&lines[start..end]));
    }

    let terminal = lines
        .iter()
        .rposition(|line| is_verifier_error_line(line.trim()))?;
    let start = lines
        .iter()
        .take(terminal + 1)
        .position(|line| is_verifier_region_start(line.trim()))?;
    Some(join_lines(&lines[start..=terminal]))
}

fn join_lines(lines: &[&str]) -> String {
    let mut joined = lines.join("\n");
    if !joined.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

fn is_verifier_region_start(line: &str) -> bool {
    line.starts_with("func#")
        || line == "Live regs before insn:"
        || parse_source_comment(line).is_some()
        || parse_instruction_pc(line).is_some()
        || line.starts_with("from ")
}

pub(crate) fn find_terminal_error(log: &str) -> Option<TerminalError> {
    let lines = log.lines().collect::<Vec<_>>();
    let mut idx = lines.len();
    while idx > 0 {
        idx -= 1;
        let line = lines[idx].trim();
        if !is_verifier_error_line(line) {
            continue;
        }

        let mut message = line.to_string();
        let mut context_idx = idx;
        if idx > 0 {
            let previous = lines[idx - 1].trim();
            if is_verifier_error_line(previous) && !previous.starts_with("libbpf:") {
                message = format!("{previous}; {message}");
                context_idx = idx - 1;
            }
        }
        let pc = nearest_instruction_pc(&lines, context_idx);
        let call_target = nearest_call_target(&lines, context_idx);
        let (source_path, source_line, source_text) = nearest_source_span(&lines, context_idx);
        return Some(TerminalError {
            line: context_idx + 1,
            message,
            pc,
            call_target,
            source_path,
            source_line,
            source_text,
        });
    }
    None
}

pub(crate) fn is_verifier_error_line(line: &str) -> bool {
    if line.is_empty()
        || line.starts_with("libbpf:")
        || line.starts_with("Error:")
        || line.starts_with("-- END")
        || instruction_tail(line).is_some()
        || (line.starts_with("processed ") && !line.contains("1000001"))
        || line.starts_with("verification time ")
        || line.starts_with("stack depth ")
        || line.starts_with("mark_precise:")
        || line.starts_with(';')
        || is_verifier_state_line(line)
    {
        return false;
    }
    let lower = line.to_ascii_lowercase();
    TERMINAL_ERROR_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn is_verifier_state_line(line: &str) -> bool {
    if line.starts_with("from ") {
        return true;
    }
    let Some((_, rest)) = line.split_once(':') else {
        return false;
    };
    let trimmed = rest.trim_start();
    trimmed.starts_with('R') || trimmed.starts_with("frame")
}

fn nearest_instruction_pc(lines: &[&str], mut idx: usize) -> Option<usize> {
    loop {
        if let Some(pc) = parse_instruction_pc(lines[idx]) {
            return Some(pc);
        }
        if idx == 0 {
            return None;
        }
        if is_backward_search_boundary(lines[idx - 1].trim()) {
            return None;
        }
        idx -= 1;
    }
}

fn nearest_call_target(lines: &[&str], mut idx: usize) -> Option<String> {
    loop {
        if let Some(tail) = instruction_tail(lines[idx]) {
            if let Some(target) = call_target_from_instruction_tail(tail) {
                return Some(target.to_string());
            }
        }
        if idx == 0 {
            return None;
        }
        if is_backward_search_boundary(lines[idx - 1].trim()) {
            return None;
        }
        idx -= 1;
    }
}

fn instruction_tail(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let colon = trimmed.find(':')?;
    if !trimmed[..colon].chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let tail = trimmed[colon + 1..].trim_start();
    instruction_opcode_tail(tail)
}

fn instruction_opcode_tail(tail: &str) -> Option<&str> {
    if looks_like_opcode_tail(tail) {
        return Some(tail);
    }
    let bytes = tail.as_bytes();
    let mask_len = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit() || **byte == b'.')
        .count();
    if mask_len > 0 && bytes.get(mask_len).is_some_and(u8::is_ascii_whitespace) {
        let rest = tail[mask_len..].trim_start();
        if looks_like_opcode_tail(rest) {
            return Some(rest);
        }
    }
    None
}

fn looks_like_opcode_tail(tail: &str) -> bool {
    let bytes = tail.as_bytes();
    bytes.len() >= 4
        && bytes[0] == b'('
        && bytes[1..3].iter().all(u8::is_ascii_hexdigit)
        && bytes[3] == b')'
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

fn nearest_source_span(
    lines: &[&str],
    mut idx: usize,
) -> (Option<String>, Option<usize>, Option<String>) {
    loop {
        if let Some(source) = parse_source_comment(lines[idx]) {
            return (Some(source.path), Some(source.line), Some(source.text));
        }
        if idx == 0 {
            return (None, None, None);
        }
        if is_backward_search_boundary(lines[idx - 1].trim()) {
            return (None, None, None);
        }
        idx -= 1;
    }
}

fn is_backward_search_boundary(line: &str) -> bool {
    line.starts_with("func#")
        || line.contains("-- BEGIN PROG LOAD LOG --")
        || line.contains("-- END PROG LOAD LOG --")
        || line.starts_with("processed ")
        || line.starts_with("verification time ")
        || line.starts_with("stack depth ")
        || (parse_instruction_pc(line).is_none() && is_verifier_error_line(line))
}

#[cfg(test)]
mod tests {
    use super::{find_terminal_error, is_verifier_error_line};

    #[test]
    fn live_regs_instruction_rows_are_not_terminal_errors() {
        assert!(!is_verifier_error_line(
            "17: ......6... (85) call bpf_rcu_read_unlock#73013"
        ));
        let log = "\
func#0 @0
Live regs before insn:
 17: ......6... (85) call bpf_rcu_read_unlock#73013
0: R1=ctx() R10=fp0
12: (79) r2 = *(u64 *)(r6 +0)         ; R2_w=rcu_ptr_or_null_bpf_cpumask(id=5)
13: (18) r1 = 0xffff8999fb071508      ; R1_w=map_value(map=.bss.MASK,ks=4,vs=8)
15: (85) call bpf_kptr_xchg#194
Possibly NULL pointer passed to helper arg2
processed 13 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
";
        let terminal = find_terminal_error(log).expect("terminal error should be found");
        assert_eq!(
            terminal.message,
            "Possibly NULL pointer passed to helper arg2"
        );
        assert_eq!(terminal.pc, Some(15));
        assert_eq!(terminal.call_target.as_deref(), Some("bpf_kptr_xchg"));
    }
}
