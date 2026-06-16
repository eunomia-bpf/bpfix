use crate::verifier_log::parse_u32_after;

pub fn active_libbpf_program_section(log: &str, before_line: usize) -> Option<&str> {
    let (program_name, window_start) = current_libbpf_program_scope(log, before_line)?;
    libbpf_section_for_program(log, window_start, before_line, program_name)
}

pub fn current_libbpf_program_scope(log: &str, before_line: usize) -> Option<(&str, usize)> {
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

pub fn libbpf_section_for_program<'a>(
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

pub fn core_relocation_struct_for_active_program(
    log: &str,
    before_line: usize,
    pc: usize,
    offset: u32,
) -> Option<&str> {
    let (program_name, window_start) = current_libbpf_program_scope(log, before_line)?;
    core_relocation_struct_for_instruction(log, window_start, before_line, program_name, pc, offset)
}

pub fn core_relocation_struct_for_instruction<'a>(
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

fn libbpf_found_program_section<'a>(line: &'a str, program_name: &str) -> Option<&'a str> {
    let (_, tail) = line.split_once("libbpf: sec '")?;
    let (section, tail) = tail.split_once("': found program '")?;
    let (found_program, _) = tail.split_once('\'')?;
    (found_program == program_name && !section.is_empty()).then_some(section)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_active_program_section_in_libbpf_log() {
        let log = "\
libbpf: loading object 'test' from buffer
libbpf: sec 'tracepoint/skb/kfree_skb': found program 'failed_prog'
libbpf: prog 'failed_prog': -- BEGIN PROG LOAD LOG --
invalid mem access 'scalar'
";

        assert_eq!(
            active_libbpf_program_section(log, 4),
            Some("tracepoint/skb/kfree_skb")
        );
        assert_eq!(
            current_libbpf_program_scope(log, 4),
            Some(("failed_prog", 2))
        );
    }

    #[test]
    fn finds_core_relocation_struct_for_active_program() {
        let log = "\
libbpf: loading object 'test' from buffer
libbpf: prog 'other_prog': relo #0: <byte_off> [1] struct inet_sock.inet_sport
libbpf: prog 'other_prog': relo #0: patched insn #1 (LDX/ST/STX) off 798 -> 798
libbpf: prog 'failed_prog': relo #0: <byte_off> [1] struct sock.sk_hash
libbpf: prog 'failed_prog': relo #0: patched insn #1 (LDX/ST/STX) off 798 -> 798
libbpf: prog 'failed_prog': -- BEGIN PROG LOAD LOG --
access beyond struct inet_sock at off 798 size 4
";

        assert_eq!(
            core_relocation_struct_for_active_program(log, 7, 1, 798),
            Some("sock")
        );
        assert_eq!(
            core_relocation_struct_for_active_program(log, 7, 2, 798),
            None
        );
    }
}
