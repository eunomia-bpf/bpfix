use bpfanalysis::verifier_log::parse_instruction_pc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLocation {
    pub path: String,
    pub line: usize,
    pub text: String,
}

#[derive(Clone, Debug)]
pub(crate) struct SourceEvent {
    pub(crate) pc: Option<usize>,
    pub(crate) log_line: usize,
    pub(crate) source: SourceLocation,
}

pub(crate) fn collect_source_events(log: &str) -> Vec<SourceEvent> {
    let lines = log.lines().collect::<Vec<_>>();
    let mut events = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(source) = parse_source_comment(line) else {
            continue;
        };
        let pc = lines
            .iter()
            .skip(idx + 1)
            .take(4)
            .find_map(|next| parse_instruction_pc(next));
        events.push(SourceEvent {
            pc,
            log_line: idx + 1,
            source,
        });
    }
    events
}

pub(crate) fn parse_source_comment(line: &str) -> Option<SourceLocation> {
    let (source, tail) = line.rsplit_once(" @ ")?;
    let (path, line_no) = tail.trim().rsplit_once(':')?;
    Some(SourceLocation {
        path: path.to_string(),
        line: line_no.parse().ok()?,
        text: source.trim().trim_start_matches(';').trim().to_string(),
    })
}

pub(crate) fn terminal_source(
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
) -> Option<SourceLocation> {
    match terminal_pc {
        Some(pc) => source_for_pc(source_events, pc).cloned(),
        None => source_events.last().map(|event| event.source.clone()),
    }
}

pub(crate) fn source_for_pc(source_events: &[SourceEvent], pc: usize) -> Option<&SourceLocation> {
    source_events
        .iter()
        .filter(|event| event.pc.is_some_and(|event_pc| event_pc <= pc))
        .max_by_key(|event| event.pc)
        .map(|event| &event.source)
}

pub(crate) fn latest_source_before<'a>(
    source_events: &'a [SourceEvent],
    rejected_source: Option<&SourceLocation>,
    predicate: impl Fn(&str) -> bool,
) -> Option<&'a SourceEvent> {
    let rejected_source = rejected_source?;
    source_events
        .iter()
        .filter(|event| event.source.path == rejected_source.path)
        .filter(|event| event.source.line < rejected_source.line)
        .filter(|event| predicate(&event.source.text))
        .max_by_key(|event| event.source.line)
}

pub(crate) fn looks_like_scalar_guard(text: &str) -> bool {
    text.starts_with("if ")
        && (text.contains('<')
            || text.contains('>')
            || text.contains("<=")
            || text.contains(">=")
            || text.contains("!=")
            || text.contains("=="))
}

pub(crate) fn looks_like_packet_bounds_check(text: &str) -> bool {
    text.starts_with("if ") && text.contains("data_end")
}

pub(crate) fn looks_like_null_check(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if !lower.starts_with("if ") {
        return false;
    }
    if lower.contains("null")
        || lower.contains("== 0")
        || lower.contains("!= 0")
        || lower.contains("== null")
        || lower.contains("!= null")
    {
        return true;
    }
    // The negated-identifier names are matched as whole identifiers. A plain
    // substring test made `!valid` match `!val` and `!value`, so a guard on an
    // unrelated flag was reported as a null check on a pointer.
    NULL_CHECK_IDENTIFIERS
        .iter()
        .any(|name| contains_negated_identifier(&lower, name))
}

const NULL_CHECK_IDENTIFIERS: [&str; 4] = ["tmp", "val", "ptr", "value"];

fn contains_negated_identifier(text: &str, name: &str) -> bool {
    let needle = format!("!{name}");
    let mut from = 0;
    while let Some(offset) = text[from..].find(&needle) {
        let start = from + offset;
        let end = start + needle.len();
        let preceded = text[..start].chars().next_back();
        let followed = text[end..].chars().next();
        let left_ok = preceded.is_none_or(|c| !is_ident_char(c));
        let right_ok = followed.is_none_or(|c| !is_ident_char(c));
        if left_ok && right_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

pub(crate) fn looks_like_nullable_return(text: &str) -> bool {
    text.contains("bpf_map_lookup_elem")
        || text.contains("bpf_ringbuf_reserve")
        || text.contains("bpf_sk_lookup")
        || text.contains("bpf_skc_lookup")
}

pub(crate) fn looks_like_stack_initialization(text: &str) -> bool {
    text.contains('=') && (text.contains("0") || text.contains("memset"))
}

pub(crate) fn looks_like_reference_acquire(text: &str) -> bool {
    text.contains("bpf_ringbuf_reserve")
        || text.contains("bpf_sk_lookup")
        || text.contains("bpf_skc_lookup")
}

pub(crate) fn looks_like_reference_release(text: &str) -> bool {
    text.contains("bpf_ringbuf_discard")
        || text.contains("bpf_ringbuf_submit")
        || text.contains("bpf_sk_release")
}

#[cfg(test)]
mod null_check_tests {
    use super::looks_like_null_check;

    #[test]
    fn negated_identifier_must_match_whole_name() {
        assert!(looks_like_null_check("if (!ptr)"));
        assert!(looks_like_null_check("if (!tmp)"));
        assert!(looks_like_null_check("if (!val)"));
        assert!(looks_like_null_check("if (!value)"));
        assert!(looks_like_null_check("if (ptr == null)"));
        assert!(looks_like_null_check("if (len == 0)"));
        // Prefixes of a listed name belong to a different identifier.
        assert!(!looks_like_null_check("if (!valid)"));
        assert!(!looks_like_null_check("if (!value_count)"));
        assert!(!looks_like_null_check("if (!ptrs)"));
        // Not a leading guard.
        assert!(!looks_like_null_check("return !ptr;"));
    }
}
