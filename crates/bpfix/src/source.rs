#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLocation {
    pub path: String,
    pub line: usize,
    pub text: String,
}

#[derive(Clone, Debug)]
pub(crate) struct SourceEvent {
    pub(crate) pc: Option<usize>,
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
        events.push(SourceEvent { pc, source });
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

pub(crate) fn parse_instruction_pc(line: &str) -> Option<usize> {
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
    lower.starts_with("if ")
        && (lower.contains("null")
            || lower.contains("!tmp")
            || lower.contains("!val")
            || lower.contains("!ptr")
            || lower.contains("!value")
            || lower.contains("== 0")
            || lower.contains("!= 0")
            || lower.contains("== null")
            || lower.contains("!= null"))
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
