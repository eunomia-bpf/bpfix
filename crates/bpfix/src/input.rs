use std::path::Path;

use anyhow::{Context, Result};

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
        if idx > 0 {
            let previous = lines[idx - 1].trim();
            if is_verifier_error_line(previous) && !previous.starts_with("libbpf:") {
                message = format!("{previous}; {message}");
            }
        }
        let pc = nearest_instruction_pc(&lines, idx);
        let (source_path, source_line, source_text) = nearest_source_span(&lines, idx);
        return Some(TerminalError {
            line: idx + 1,
            message,
            pc,
            source_path,
            source_line,
            source_text,
        });
    }
    None
}

fn is_verifier_error_line(line: &str) -> bool {
    if line.is_empty()
        || line.starts_with("libbpf:")
        || line.starts_with("Error:")
        || line.starts_with("-- END")
        || (line.starts_with("processed ") && !line.contains("1000001"))
        || line.starts_with("verification time ")
        || line.starts_with("stack depth ")
        || line.starts_with("mark_precise:")
        || line.starts_with(';')
    {
        return false;
    }
    let lower = line.to_ascii_lowercase();
    let markers = [
        "bpf program is too large",
        "combined stack size",
        "invalid ",
        "unbounded",
        "out of bounds",
        "outside of",
        "expected ",
        "expected=",
        "misaligned",
        "missing btf",
        "unknown opcode",
        "unknown func",
        "invalid args",
        "invalid argument",
        "caller passes invalid args",
        "arg#",
        "unreleased reference",
        "reference has not",
        "helper call is not allowed",
        "helper access to the packet is not allowed",
        "cannot use helper",
        "calling kernel function",
        "jit does not support",
        "cannot ",
        "permission denied",
        "too many states",
        "processed 1000001",
        "loop is not bounded",
        "infinite loop detected",
        "back-edge",
        "misaligned",
        "same insn cannot be used with different pointers",
        "pointer arithmetic",
        "cannot restore irq",
        "rcu",
        "lock",
        "kfunc",
        "trusted",
        "iterator",
        "iter",
        "min value is negative",
        "min value is outside",
        "dereference of modified ctx ptr",
        "makes pkt pointer",
        "type=",
        "r0 !read_ok",
        "!read_ok",
        "only read from",
        "access beyond struct",
        "has no valid kptr",
        "dynptr",
    ];
    markers.iter().any(|marker| lower.contains(marker))
}

fn nearest_instruction_pc(lines: &[&str], mut idx: usize) -> Option<usize> {
    loop {
        if let Some(pc) = parse_instruction_pc(lines[idx]) {
            return Some(pc);
        }
        if idx == 0 {
            return None;
        }
        idx -= 1;
    }
}

fn parse_instruction_pc(line: &str) -> Option<usize> {
    let trimmed = line.trim_start();
    let digits_len = trimmed
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits_len == 0 || trimmed.as_bytes().get(digits_len) != Some(&b':') {
        return None;
    }
    trimmed[..digits_len].parse().ok()
}

fn nearest_source_span(
    lines: &[&str],
    mut idx: usize,
) -> (Option<String>, Option<usize>, Option<String>) {
    loop {
        if let Some((path, line, source_text)) = parse_source_comment(lines[idx]) {
            return (Some(path), Some(line), Some(source_text));
        }
        if idx == 0 {
            return (None, None, None);
        }
        idx -= 1;
    }
}

fn parse_source_comment(line: &str) -> Option<(String, usize, String)> {
    let (source, tail) = line.rsplit_once(" @ ")?;
    let tail = tail.trim();
    let (path, line_no) = tail.rsplit_once(':')?;
    let line_no = line_no.parse().ok()?;
    let source = source.trim().trim_start_matches(';').trim().to_string();
    Some((path.to_string(), line_no, source))
}
