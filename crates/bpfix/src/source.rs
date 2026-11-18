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
    let line_no: usize = line_no.parse().ok()?;
    // Clang emits an empty source comment with line 0 for a program with no
    // source text at that instruction. Reporting it as a location makes
    // consumers treat the diagnostic as having no span at all, so skip it and
    // let the caller fall back to a real source event or the verifier line.
    let text = source.trim().trim_start_matches(';').trim();
    if line_no == 0 && text.is_empty() {
        return None;
    }
    Some(SourceLocation {
        path: path.to_string(),
        line: line_no,
        text: text.to_string(),
    })
}

/// A source line the verifier log quotes without its location.
///
/// Kernels before 6.9 print `; <source text>` and omit ` @ file:line`, so this
/// must not mistake a located line for an unlocated one.
pub(crate) fn parse_source_text(line: &str) -> Option<&str> {
    let text = line.trim();
    let text = text.strip_prefix(';')?;
    if line.contains(" @ ") {
        return None;
    }
    let text = text.trim();
    (!text.is_empty()).then_some(text)
}

/// Resolve a quoted source line against the object's BTF line table.
///
/// Only a text that appears exactly once is a location; a repeated line (a
/// closing brace, a common `return 0;`) would otherwise point at an arbitrary
/// occurrence, which is worse than admitting the log has no location.
pub(crate) fn source_location_from_btf(
    records: &[bpfanalysis::BtfLineRecord],
    text: &str,
) -> Option<SourceLocation> {
    // One source line yields several records, one per instruction it produced
    // (`if (data + 74 > data_end)` becomes a load and a compare). Uniqueness is
    // about the source location, so collapse the records by `file:line` first.
    let mut locations = records
        .iter()
        .filter(|record| record.text.trim() == text)
        .map(|record| (&record.file, record.line))
        .collect::<Vec<_>>();
    locations.sort_unstable();
    locations.dedup();
    let [(path, line)] = locations.as_slice() else {
        return None;
    };
    Some(SourceLocation {
        path: (*path).clone(),
        line: *line as usize,
        text: text.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(file: &str, line: u32, text: &str) -> bpfanalysis::BtfLineRecord {
        bpfanalysis::BtfLineRecord {
            insn_off: 0,
            file: file.to_string(),
            line,
            text: text.to_string(),
        }
    }

    #[test]
    fn unlocated_source_text_ignores_located_lines() {
        assert_eq!(parse_source_text("; if (x)"), Some("if (x)"));
        assert_eq!(parse_source_text("   ;  return 0;  "), Some("return 0;"));
        assert_eq!(parse_source_text("; if (x) @ prog.c:4"), None);
        assert_eq!(parse_source_text("24: (0f) r2 += r1"), None);
        assert_eq!(parse_source_text(";"), None);
    }

    #[test]
    fn a_text_at_two_source_lines_stays_unresolved() {
        let records = vec![record("prog.c", 4, "return 0;"), record("prog.c", 9, "return 0;")];
        assert_eq!(source_location_from_btf(&records, "return 0;"), None);
    }

    #[test]
    fn repeated_records_for_one_line_resolve() {
        let records = vec![
            record("prog.c", 29, "if (data + 74 > data_end)"),
            record("prog.c", 29, "if (data + 74 > data_end)"),
        ];
        let location = source_location_from_btf(&records, "if (data + 74 > data_end)").unwrap();
        assert_eq!((location.path.as_str(), location.line), ("prog.c", 29));
    }

    #[test]
    fn missing_text_resolves_to_nothing() {
        let records = vec![record("prog.c", 4, "return 0;")];
        assert_eq!(source_location_from_btf(&records, "return 1;"), None);
    }
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

#[cfg(test)]
mod source_comment_tests {
    use super::parse_source_comment;

    #[test]
    fn empty_source_comment_with_line_zero_is_skipped() {
        // Shape emitted by clang when an instruction has no source text.
        assert_eq!(parse_source_comment(";  @ buggy.bpf.c:0"), None);
    }

    #[test]
    fn source_comment_with_text_and_line_is_kept() {
        let parsed = parse_source_comment("; return *entry; @ buggy.bpf.c:13").expect("parsed");
        assert_eq!(parsed.line, 13);
        assert_eq!(parsed.text, "return *entry;");
    }
}
