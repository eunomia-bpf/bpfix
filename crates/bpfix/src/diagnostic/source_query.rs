use crate::source::{SourceEvent, SourceLocation};

use super::{ProofEvent, ProofEventRole};

pub(super) fn source_for_instruction_in_fragment(
    source_events: &[SourceEvent],
    pc: usize,
    fragment_start_line: usize,
    instruction_line: usize,
) -> Option<&SourceLocation> {
    source_events
        .iter()
        .filter(|event| event.log_line >= fragment_start_line)
        .filter(|event| event.log_line < instruction_line)
        .filter(|event| event.pc.is_some_and(|event_pc| event_pc <= pc))
        .max_by_key(|event| (event.pc.unwrap_or(0), event.log_line))
        .map(|event| &event.source)
}

pub(super) fn rejected_source(events: &[ProofEvent]) -> Option<&SourceLocation> {
    events
        .iter()
        .find(|event| event.role == ProofEventRole::Rejected)
        .and_then(|event| event.source.as_ref())
}

pub(super) fn source_for_pc_in_rejected_file(
    source_events: &[SourceEvent],
    pc: usize,
    rejected: Option<&SourceLocation>,
) -> Option<SourceLocation> {
    let rejected = rejected?;
    let source = source_events
        .iter()
        .filter(|event| event.source.path == rejected.path)
        .filter(|event| event.pc.is_some_and(|event_pc| event_pc <= pc))
        .max_by_key(|event| event.pc)?
        .source
        .clone();
    (!same_source_location(&source, rejected)).then_some(source)
}

pub(super) fn same_source_location(left: &SourceLocation, right: &SourceLocation) -> bool {
    left.path == right.path && left.line == right.line && left.text == right.text
}

pub(super) fn first_call_argument(source_text: &str, function: &str) -> Option<String> {
    call_argument(source_text, function, 0)
}

pub(super) fn invalid_args_function_name(terminal_error: &str) -> Option<&str> {
    let (_, after_open) = terminal_error.rsplit_once("('")?;
    let (name, _) = after_open.split_once("')")?;
    (!name.is_empty()).then_some(name)
}

pub(super) fn call_argument(
    source_text: &str,
    function: &str,
    argument_index: usize,
) -> Option<String> {
    let open = source_text.find(function)? + function.len();
    let mut chars = source_text[open..].char_indices();
    let (_, first) = chars.next()?;
    if first != '(' {
        return None;
    }
    let args_start = open + first.len_utf8();
    let mut arg_start = args_start;
    let mut current_argument = 0usize;
    let mut depth = 0usize;
    for (relative_idx, ch) in chars {
        let absolute_idx = open + relative_idx;
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => {
                return (current_argument == argument_index)
                    .then(|| source_text[arg_start..absolute_idx].trim().to_string());
            }
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                if current_argument == argument_index {
                    return Some(source_text[arg_start..absolute_idx].trim().to_string());
                }
                current_argument += 1;
                arg_start = absolute_idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    None
}

pub(super) fn is_bare_identifier_argument(argument: &str) -> bool {
    let argument = argument.trim();
    let mut chars = argument.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_literal_null_argument(argument: &str) -> bool {
    let normalized = argument
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if matches!(normalized.as_str(), "null" | "(void*)null") {
        return true;
    }
    let suffixless_zero = normalized.trim_end_matches(['u', 'l']) == "0";
    suffixless_zero
        || matches!(normalized.as_str(), "(void*)0")
        || (normalized.starts_with('(')
            && (normalized.ends_with(")0") || normalized.ends_with(")null"))
            && normalized.contains('*'))
}

pub(super) fn map_argument_has_relocation_proof(
    argument: &str,
    rejected: &SourceLocation,
    source_events: &[SourceEvent],
) -> bool {
    if is_literal_null_argument(argument) {
        return false;
    }
    // Corpus reconstructions use this explicit marker when the original report
    // loaded raw instructions and lost the map relocation before verification.
    if is_reconstructed_missing_relocation_argument(argument) {
        return true;
    }
    let Some(symbol) = addressed_identifier(argument) else {
        return false;
    };
    source_has_map_symbol_declaration(source_events, rejected, &symbol)
}

fn is_reconstructed_missing_relocation_argument(argument: &str) -> bool {
    identifier_tokens(argument)
        .iter()
        .any(|identifier| identifier == "missing_relocation")
}

fn addressed_identifier(argument: &str) -> Option<String> {
    let ampersand = argument.rfind('&')?;
    let prefix = argument[..ampersand].trim();
    if !(prefix.is_empty() || prefix.ends_with(')')) {
        return None;
    }
    let rest = argument[ampersand + 1..].trim_start();
    let ident_len = rest
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if ident_len == 0 {
        return None;
    }
    if !rest[ident_len..].trim().is_empty() {
        return None;
    }
    Some(rest[..ident_len].to_string())
}

fn source_has_map_symbol_declaration(
    source_events: &[SourceEvent],
    rejected: &SourceLocation,
    symbol: &str,
) -> bool {
    source_events.iter().any(|event| {
        event.source.path == rejected.path
            && event.source.line <= rejected.line
            && source_line_declares_map_symbol(&event.source.text, symbol)
    })
}

fn source_line_declares_map_symbol(text: &str, symbol: &str) -> bool {
    if !identifier_tokens(text)
        .iter()
        .any(|identifier| identifier == symbol)
    {
        return false;
    }
    let compact = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    compact.contains("sec(\".maps\")")
        || compact.contains("sec(\"maps\")")
        || compact.contains("__section(\".maps\")")
        || compact.contains("__section(\"maps\")")
}

pub(super) fn max_numeric_token(text: &str) -> Option<u32> {
    numeric_tokens(text).into_iter().max()
}

pub(super) fn numeric_tokens(text: &str) -> Vec<u32> {
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    let mut tokens = Vec::new();
    while idx < bytes.len() {
        if !bytes[idx].is_ascii_digit() {
            idx += 1;
            continue;
        }
        let start = idx;
        idx += 1;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if let Ok(value) = text[start..idx].parse::<u32>() {
            tokens.push(value);
        }
    }
    tokens
}

pub(super) fn identifier_tokens(text: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut start = None;
    for (idx, ch) in text.char_indices() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            start.get_or_insert(idx);
            continue;
        }
        if let Some(token_start) = start.take() {
            push_meaningful_identifier(&mut identifiers, &text[token_start..idx]);
        }
    }
    if let Some(token_start) = start {
        push_meaningful_identifier(&mut identifiers, &text[token_start..]);
    }
    identifiers
}

fn push_meaningful_identifier(identifiers: &mut Vec<String>, token: &str) {
    if (token.len() < 2 && !matches!(token, "i" | "j" | "k"))
        || token.as_bytes()[0].is_ascii_digit()
        || matches!(
            token,
            "if" | "void"
                | "char"
                | "unsigned"
                | "int"
                | "__u8"
                | "__u16"
                | "__u32"
                | "__u64"
                | "data"
                | "data_end"
                | "byte"
        )
    {
        return;
    }
    identifiers.push(token.to_string());
}

pub(super) fn looks_like_packet_pointer_derivation(text: &str) -> bool {
    let text = text.trim();
    if text.starts_with("if ") || !text.contains('=') || !text.contains('+') {
        return false;
    }
    let Some((lhs, _)) = text.split_once('=') else {
        return false;
    };
    lhs.contains('*')
}
