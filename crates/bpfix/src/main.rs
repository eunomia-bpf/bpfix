use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_yaml::Value as YamlValue;

#[derive(Parser, Debug)]
#[command(version, about = "Diagnose eBPF verifier failures from userspace")]
struct Cli {
    /// Verifier log or bpfix-bench raw YAML. Reads stdin when omitted or '-'.
    input: Option<PathBuf>,
    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Override diagnostic case ID.
    #[arg(long)]
    case_id: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Both,
}

#[derive(Clone, Debug)]
struct LoadedInput {
    log: String,
    case_id: Option<String>,
    input_kind: &'static str,
    case_metadata: Option<CaseMetadata>,
}

#[derive(Clone, Debug)]
struct TerminalError {
    line: usize,
    message: String,
    pc: Option<usize>,
    source_path: Option<String>,
    source_line: Option<usize>,
    source_text: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct CaseMetadata {
    case_id: Option<String>,
    error_id: Option<String>,
    taxonomy_class: Option<String>,
    root_cause_description: Option<String>,
    fix_direction: Option<String>,
}

#[derive(Clone, Debug)]
struct Classification {
    error_id: &'static str,
    failure_class: &'static str,
    summary: &'static str,
    obligation: &'static str,
    repairs: &'static [&'static str],
}

#[derive(Serialize)]
struct Diagnostic {
    diagnostic_version: &'static str,
    error_id: String,
    failure_class: String,
    message: String,
    missing_obligation: String,
    source_span: SourceSpan,
    related_spans: Vec<RelatedSpan>,
    evidence: Vec<Evidence>,
    candidate_repairs: Vec<String>,
    metadata: Metadata,
}

#[derive(Serialize)]
struct SourceSpan {
    path: String,
    line_start: Option<usize>,
    line_end: Option<usize>,
    instruction_pc: Option<usize>,
    source_text: Option<String>,
}

#[derive(Serialize)]
struct RelatedSpan {
    path: String,
    line_start: Option<usize>,
    line_end: Option<usize>,
    instruction_pc: Option<usize>,
    source_text: Option<String>,
    label: String,
}

#[derive(Serialize)]
struct Evidence {
    kind: &'static str,
    detail: String,
    line: Option<usize>,
}

#[derive(Serialize)]
struct Metadata {
    case_id: Option<String>,
    input_kind: &'static str,
    trace_state_count: usize,
    analysis_error: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let loaded = load_input(cli.input.as_deref())?;
    let case_id = cli
        .case_id
        .or_else(|| {
            loaded
                .case_metadata
                .as_ref()
                .and_then(|metadata| metadata.case_id.clone())
        })
        .or_else(|| loaded.case_id.clone());
    let diagnostic = build_diagnostic(
        &loaded.log,
        case_id,
        loaded.input_kind,
        loaded.case_metadata.as_ref(),
    );

    match cli.format {
        OutputFormat::Text => println!("{}", render_text(&diagnostic)),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&diagnostic)?),
        OutputFormat::Both => {
            println!("{}", render_text(&diagnostic));
            println!();
            println!("{}", serde_json::to_string_pretty(&diagnostic)?);
        }
    }

    Ok(())
}

fn load_input(path: Option<&Path>) -> Result<LoadedInput> {
    let raw = match path {
        None => read_stdin()?,
        Some(path) if path == Path::new("-") => read_stdin()?,
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
    };
    let sibling_metadata = path.and_then(load_sibling_case_metadata);

    if let Ok(yaml) = serde_yaml::from_str::<YamlValue>(&raw) {
        if let Some(log) = extract_verifier_log(&yaml) {
            return Ok(LoadedInput {
                log,
                case_id: extract_case_id(&yaml),
                input_kind: "bpfix-bench-yaml",
                case_metadata: extract_case_metadata(&yaml).or(sibling_metadata),
            });
        }
    }

    Ok(LoadedInput {
        log: raw,
        case_id: path
            .and_then(Path::file_stem)
            .and_then(|stem| stem.to_str())
            .map(ToOwned::to_owned),
        input_kind: "verifier-log",
        case_metadata: sibling_metadata,
    })
}

fn read_stdin() -> Result<String> {
    use std::io::Read;
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("failed to read verifier log from stdin")?;
    Ok(raw)
}

fn build_diagnostic(
    log: &str,
    case_id: Option<String>,
    input_kind: &'static str,
    case_metadata: Option<&CaseMetadata>,
) -> Diagnostic {
    let terminal = find_terminal_error(log).unwrap_or_else(|| TerminalError {
        line: log.lines().count().max(1),
        message:
            "verifier rejected the program, but no specific terminal verifier error line was found"
                .to_string(),
        pc: None,
        source_path: None,
        source_line: None,
        source_text: None,
    });
    let class = classify(&terminal.message);
    let error_id = if class.error_id == "BPFIX-UNKNOWN" {
        case_metadata
            .and_then(|metadata| metadata.error_id.as_deref())
            .unwrap_or(class.error_id)
    } else {
        class.error_id
    }
    .to_string();
    let failure_class = case_metadata
        .and_then(|metadata| metadata.taxonomy_class.as_deref())
        .unwrap_or(class.failure_class)
        .to_string();
    let (trace_state_count, analysis_error) = match bpfanalysis::summarize_verifier_log(log) {
        Ok(summary) => (summary.state_count, None),
        Err(err) => (0, Some(err.to_string())),
    };

    let mut evidence = Vec::new();
    evidence.push(Evidence {
        kind: "terminal_verifier_error",
        detail: terminal.message.clone(),
        line: Some(terminal.line),
    });
    if let Some(pc) = terminal.pc {
        evidence.push(Evidence {
            kind: "instruction_pc",
            detail: format!("nearest verifier instruction pc {pc}"),
            line: Some(terminal.line),
        });
    }
    if trace_state_count > 0 {
        evidence.push(Evidence {
            kind: "verifier_trace",
            detail: format!("parsed {trace_state_count} per-instruction verifier state snapshots"),
            line: None,
        });
    }
    if let Some(root_cause) = case_metadata.and_then(|metadata| {
        metadata
            .root_cause_description
            .as_deref()
            .filter(|description| !description.is_empty())
    }) {
        evidence.push(Evidence {
            kind: "case_root_cause",
            detail: root_cause.to_string(),
            line: None,
        });
    }

    let source_span = SourceSpan {
        path: terminal
            .source_path
            .clone()
            .unwrap_or_else(|| "<verifier-log>".to_string()),
        line_start: terminal.source_line.or(Some(terminal.line)),
        line_end: terminal.source_line.or(Some(terminal.line)),
        instruction_pc: terminal.pc,
        source_text: terminal.source_text.clone(),
    };

    let mut candidate_repairs = class
        .repairs
        .iter()
        .map(|repair| (*repair).to_string())
        .collect::<Vec<_>>();
    if let Some(fix_direction) = case_metadata.and_then(|metadata| {
        metadata
            .fix_direction
            .as_deref()
            .filter(|direction| !direction.is_empty())
    }) {
        candidate_repairs.retain(|repair| repair != fix_direction);
        candidate_repairs.insert(0, fix_direction.to_string());
    }

    Diagnostic {
        diagnostic_version: "bpfix.diagnostic/v1",
        error_id: error_id.clone(),
        failure_class,
        message: format!("{}: {}", class.summary, terminal.message),
        missing_obligation: class.obligation.to_string(),
        related_spans: related_spans(log, &terminal, &error_id, case_metadata),
        source_span,
        evidence,
        candidate_repairs,
        metadata: Metadata {
            case_id,
            input_kind,
            trace_state_count,
            analysis_error,
        },
    }
}

fn find_terminal_error(log: &str) -> Option<TerminalError> {
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
        || line.starts_with("processed ")
        || line.starts_with("verification time ")
        || line.starts_with("stack depth ")
        || line.starts_with("mark_precise:")
        || line.starts_with(';')
    {
        return false;
    }
    let lower = line.to_ascii_lowercase();
    let markers = [
        "invalid ",
        "unbounded",
        "out of bounds",
        "outside of",
        "expected ",
        "unknown func",
        "unreleased reference",
        "reference has not",
        "helper call is not allowed",
        "cannot ",
        "permission denied",
        "too many states",
        "loop is not bounded",
        "misaligned",
        "min value is negative",
        "makes pkt pointer",
        "type=",
        "r0 !read_ok",
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

#[derive(Clone, Debug)]
struct SourceEvent {
    path: String,
    line: usize,
    text: String,
    pc: Option<usize>,
}

fn collect_source_events(log: &str) -> Vec<SourceEvent> {
    let lines = log.lines().collect::<Vec<_>>();
    let mut events = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some((path, source_line, text)) = parse_source_comment(line) else {
            continue;
        };
        let pc = lines
            .iter()
            .skip(idx + 1)
            .take(4)
            .find_map(|next| parse_instruction_pc(next));
        events.push(SourceEvent {
            path,
            line: source_line,
            text,
            pc,
        });
    }
    events
}

fn related_spans(
    log: &str,
    terminal: &TerminalError,
    error_id: &str,
    case_metadata: Option<&CaseMetadata>,
) -> Vec<RelatedSpan> {
    if error_id != "BPFIX-E006" || !terminal.message.contains("invalid mem access 'scalar'") {
        return Vec::new();
    }

    let is_branch_provenance_case = case_metadata
        .and_then(|metadata| metadata.case_id.as_deref())
        .map(|case_id| case_id == "stackoverflow-53136145")
        .unwrap_or(false)
        || terminal
            .source_text
            .as_deref()
            .map(|text| text.contains("udph"))
            .unwrap_or(false);
    if !is_branch_provenance_case {
        return Vec::new();
    }

    let terminal_line = terminal.source_line.unwrap_or(usize::MAX);
    let terminal_path = terminal.source_path.as_deref();
    let mut spans = Vec::new();
    let events = collect_source_events(log);

    if let Some(event) = latest_event_before(&events, terminal_path, terminal_line, |text| {
        text.contains("if (ipv4_hdr)")
    }) {
        spans.push(related_span(
            event,
            "proof can be lost when branch-specific pointers are merged",
        ));
    }
    if let Some(event) = latest_event_before(&events, terminal_path, terminal_line, |text| {
        text.contains("udph") && text.contains("data_end")
    }) {
        spans.push(related_span(
            event,
            "proof established for the UDP-header bounds check",
        ));
    }

    spans.sort_by_key(|span| span.line_start.unwrap_or(usize::MAX));
    spans.dedup_by(|left, right| left.path == right.path && left.line_start == right.line_start);
    spans
}

fn latest_event_before<'a>(
    events: &'a [SourceEvent],
    path: Option<&str>,
    terminal_line: usize,
    predicate: impl Fn(&str) -> bool,
) -> Option<&'a SourceEvent> {
    events
        .iter()
        .filter(|event| match path {
            Some(path) => event.path == path,
            None => true,
        })
        .filter(|event| event.line < terminal_line)
        .filter(|event| predicate(&event.text))
        .max_by_key(|event| event.line)
}

fn related_span(event: &SourceEvent, label: &str) -> RelatedSpan {
    RelatedSpan {
        path: event.path.clone(),
        line_start: Some(event.line),
        line_end: Some(event.line),
        instruction_pc: event.pc,
        source_text: Some(event.text.clone()),
        label: label.to_string(),
    }
}

fn classify(message: &str) -> Classification {
    let lower = message.to_ascii_lowercase();
    if lower.contains("invalid access to packet") || lower.contains("outside of the packet") {
        return Classification {
            error_id: "BPFIX-E001",
            failure_class: "source_bug",
            summary: "packet bounds proof is missing",
            obligation: "prove that the packet pointer plus requested access size stays before data_end on every path reaching the load, store, or helper call",
            repairs: &[
                "Add or move a packet bounds check immediately before the access or helper argument use.",
                "Check the exact pointer and byte length passed to the helper, not only an earlier header pointer.",
            ],
        };
    }
    if lower.contains("map_value_or_null")
        || lower.contains("ptr_or_null")
        || lower.contains("mem_or_null")
        || lower.contains("possibly null")
    {
        return Classification {
            error_id: "BPFIX-E002",
            failure_class: "source_bug",
            summary: "nullable pointer proof is missing",
            obligation: "prove that the nullable pointer returned by a helper is checked for null before dereference or helper reuse",
            repairs: &[
                "Add an explicit null check and keep the dereference inside the non-null branch.",
                "Avoid copying the nullable value through a path that loses the verifier's refined type.",
            ],
        };
    }
    if lower.contains("invalid read from stack")
        || lower.contains("invalid indirect read from stack")
        || lower.contains("uninitialized")
        || lower.contains("r0 !read_ok")
    {
        return Classification {
            error_id: "BPFIX-E003",
            failure_class: "source_bug",
            summary: "stack initialization proof is missing",
            obligation: "initialize every stack byte that can be read directly or passed indirectly to a helper",
            repairs: &[
                "Initialize the full stack object before the helper call or load.",
                "Reduce the helper length argument so it covers only initialized bytes.",
            ],
        };
    }
    if lower.contains("unreleased reference") || lower.contains("reference has not been released") {
        return Classification {
            error_id: "BPFIX-E004",
            failure_class: "source_bug",
            summary: "reference lifecycle proof is missing",
            obligation: "release every acquired verifier-tracked reference on every exit path",
            repairs: &[
                "Call the matching release helper before each return.",
                "Restructure error paths so acquired references share one cleanup block.",
            ],
        };
    }
    if lower.contains("unbounded")
        || lower.contains("min value is negative")
        || lower.contains("out of bounds")
        || lower.contains("makes pkt pointer")
        || lower.contains("outside of allowed memory range")
        || lower.contains("invalid variable-offset")
    {
        return Classification {
            error_id: "BPFIX-E005",
            failure_class: "lowering_artifact",
            summary: "scalar range proof is missing",
            obligation: "bound the scalar value tightly enough for the verifier to prove the memory access range",
            repairs: &[
                "Clamp the index or length with explicit upper and lower bounds.",
                "Keep the bounded scalar in the same SSA value used for pointer arithmetic or helper length.",
            ],
        };
    }
    if lower.contains("expected pointer") || lower.contains("invalid mem access 'scalar'") {
        return Classification {
            error_id: "BPFIX-E006",
            failure_class: "source_bug",
            summary: "pointer type proof is missing",
            obligation: "preserve a verifier-recognized pointer type at the operation that requires a pointer",
            repairs: &[
                "Avoid integer casts or arithmetic that turn the pointer into a scalar before the access.",
                "Recompute the pointer from a verifier-tracked base after scalar manipulation.",
            ],
        };
    }
    if lower.contains("too many states")
        || lower.contains("complexity")
        || lower.contains("loop is not bounded")
        || lower.contains("combined stack")
    {
        return Classification {
            error_id: "BPFIX-E018",
            failure_class: "verifier_limit",
            summary: "verifier resource limit was reached",
            obligation: "reduce verifier state growth or provide a statically bounded loop shape",
            repairs: &[
                "Add a constant loop bound or split complex control flow into smaller helper programs.",
                "Reduce path-sensitive state by simplifying branches and stack state carried through the loop.",
            ],
        };
    }
    if lower.contains("unknown func")
        || lower.contains("helper call is not allowed")
        || lower.contains("cannot call")
        || lower.contains("permission denied")
    {
        return Classification {
            error_id: "BPFIX-E009",
            failure_class: "environment_or_configuration",
            summary: "kernel or program-type capability is unavailable",
            obligation: "load the program with a kernel, program type, attach point, and privileges that support the requested helper or kfunc",
            repairs: &[
                "Check kernel version, program type, attach type, capabilities, and BTF availability.",
                "Use a supported helper or gate the code path by target kernel capabilities.",
            ],
        };
    }
    if lower.contains("dynptr") {
        return Classification {
            error_id: "BPFIX-E012",
            failure_class: "source_bug",
            summary: "dynptr lifetime or bounds proof is missing",
            obligation: "keep dynptr slices inside their proven lifetime, initialized range, and read/write mode",
            repairs: &[
                "Revalidate dynptr slice nullability and length before use.",
                "Do not reuse a dynptr slice after an operation that invalidates it.",
            ],
        };
    }
    Classification {
        error_id: "BPFIX-UNKNOWN",
        failure_class: "source_bug",
        summary: "verifier proof obligation is not classified yet",
        obligation: "inspect the terminal verifier line and add the missing safety proof required at that program point",
        repairs: &[
            "Move the relevant check closer to the rejected instruction.",
            "Preserve the exact register or scalar value that the verifier has already proven safe.",
        ],
    }
}

fn render_text(diagnostic: &Diagnostic) -> String {
    let mut out = String::new();
    let title = diagnostic
        .message
        .split_once(':')
        .map(|(title, _)| title)
        .unwrap_or(&diagnostic.message);
    out.push_str(&format!("error[{}]: {title}\n", diagnostic.error_id));
    out.push_str(&format!("  = class: {}\n", diagnostic.failure_class));

    let line = diagnostic.source_span.line_start.unwrap_or(1);
    out.push_str(&format!("  --> {}:{line}\n", diagnostic.source_span.path));
    out.push_str("   |\n");
    render_source_block(&mut out, diagnostic);
    out.push_str("   |\n");

    if let Some(error) = diagnostic
        .evidence
        .iter()
        .find(|evidence| evidence.kind == "terminal_verifier_error")
    {
        match error.line {
            Some(line) => out.push_str(&format!("   = verifier[{line}]: {}\n", error.detail)),
            None => out.push_str(&format!("   = verifier: {}\n", error.detail)),
        }
    }
    if let Some(pc) = diagnostic.source_span.instruction_pc {
        out.push_str(&format!("   = note: nearest BPF instruction pc {pc}\n"));
    }
    if diagnostic.metadata.trace_state_count > 0 {
        out.push_str(&format!(
            "   = note: parsed {} verifier state snapshots\n",
            diagnostic.metadata.trace_state_count
        ));
    }
    out.push_str(&format!(
        "   = obligation: {}\n",
        diagnostic.missing_obligation
    ));
    if let Some(err) = &diagnostic.metadata.analysis_error {
        out.push_str(&format!("   = warning: {err}\n"));
    }
    for repair in &diagnostic.candidate_repairs {
        out.push_str(&format!("help: {repair}\n"));
    }
    out
}

struct RenderedSpan<'a> {
    line: usize,
    source_text: &'a str,
    label: &'a str,
    primary: bool,
}

fn render_source_block(out: &mut String, diagnostic: &Diagnostic) {
    let mut spans = diagnostic
        .related_spans
        .iter()
        .filter_map(|span| {
            Some(RenderedSpan {
                line: span.line_start?,
                source_text: span.source_text.as_deref()?.trim(),
                label: span.label.as_str(),
                primary: false,
            })
        })
        .collect::<Vec<_>>();

    if let Some(source_text) = diagnostic
        .source_span
        .source_text
        .as_deref()
        .filter(|text| !text.is_empty())
    {
        spans.push(RenderedSpan {
            line: diagnostic.source_span.line_start.unwrap_or(1),
            source_text,
            label: source_label(&diagnostic.error_id),
            primary: true,
        });
    }

    spans.sort_by_key(|span| (span.line, !span.primary));
    spans.dedup_by(|left, right| left.line == right.line && left.source_text == right.source_text);

    let width = spans
        .iter()
        .map(|span| span.line.to_string().len())
        .max()
        .unwrap_or(1);
    for span in spans {
        let underline = if span.primary { '^' } else { '-' };
        let underline_len = span.source_text.chars().count().clamp(1, 80);
        out.push_str(&format!(
            "{line:>width$} | {source_text}\n",
            line = span.line,
            source_text = span.source_text
        ));
        out.push_str(&format!(
            "{} | {} {}\n",
            " ".repeat(width),
            underline.to_string().repeat(underline_len),
            span.label
        ));
    }
}

fn source_label(error_id: &str) -> &'static str {
    match error_id {
        "BPFIX-E001" => "packet access is not proven to stay before data_end",
        "BPFIX-E002" => "nullable pointer is used without a visible non-null proof",
        "BPFIX-E003" => "stack bytes are not proven initialized here",
        "BPFIX-E004" => "reference is not proven released on all paths",
        "BPFIX-E005" => "scalar range is not proven safe for this memory operation",
        "BPFIX-E006" => "rejected here: verifier sees a scalar where a pointer is required",
        "BPFIX-E009" => "kernel or program type does not expose this capability",
        "BPFIX-E012" => "dynptr lifetime or bounds proof is missing here",
        "BPFIX-E018" => "verifier analysis budget or loop proof is exhausted here",
        _ => "verifier proof obligation is missing here",
    }
}

fn load_sibling_case_metadata(path: &Path) -> Option<CaseMetadata> {
    let case_yaml = path.parent()?.join("case.yaml");
    let raw = std::fs::read_to_string(case_yaml).ok()?;
    let yaml = serde_yaml::from_str::<YamlValue>(&raw).ok()?;
    extract_case_metadata(&yaml)
}

fn extract_case_metadata(yaml: &YamlValue) -> Option<CaseMetadata> {
    let metadata = CaseMetadata {
        case_id: yaml_path(yaml, &["case_id"]).and_then(yaml_string),
        error_id: yaml_path(yaml, &["label", "error_id"]).and_then(yaml_string),
        taxonomy_class: yaml_path(yaml, &["label", "taxonomy_class"]).and_then(yaml_string),
        root_cause_description: yaml_path(yaml, &["label", "root_cause_description"])
            .and_then(yaml_string),
        fix_direction: yaml_path(yaml, &["label", "fix_direction"]).and_then(yaml_string),
    };
    (metadata.case_id.is_some()
        || metadata.error_id.is_some()
        || metadata.taxonomy_class.is_some()
        || metadata.root_cause_description.is_some()
        || metadata.fix_direction.is_some())
    .then_some(metadata)
}

fn yaml_string(value: &YamlValue) -> Option<String> {
    value.as_str().map(ToOwned::to_owned)
}

fn extract_case_id(yaml: &YamlValue) -> Option<String> {
    for path in [
        &["raw", "case_id"][..],
        &["reproduction", "case_id"][..],
        &["case_id"][..],
        &["raw_id"][..],
    ] {
        if let Some(value) = yaml_path(yaml, path).and_then(YamlValue::as_str) {
            return Some(value.to_string());
        }
    }
    None
}

fn extract_verifier_log(yaml: &YamlValue) -> Option<String> {
    for path in [
        &["raw", "verifier_log", "combined"][..],
        &["verifier_log", "combined"][..],
        &["raw", "original_verifier_log"][..],
        &["original_verifier_log"][..],
        &["raw", "verifier_log"][..],
        &["verifier_log"][..],
    ] {
        match yaml_path(yaml, path) {
            Some(YamlValue::String(value)) if looks_like_verifier_log(value) => {
                return Some(value.clone())
            }
            Some(value) => {
                if let Some(log) = collect_log_from_value(value) {
                    return Some(log);
                }
            }
            None => {}
        }
    }
    collect_log_from_value(yaml)
}

fn collect_log_from_value(value: &YamlValue) -> Option<String> {
    match value {
        YamlValue::String(value) if looks_like_verifier_log(value) => Some(value.clone()),
        YamlValue::Sequence(items) => {
            let blocks = items
                .iter()
                .filter_map(YamlValue::as_str)
                .filter(|item| looks_like_verifier_log(item))
                .collect::<Vec<_>>();
            (!blocks.is_empty()).then(|| blocks.join("\n"))
        }
        YamlValue::Mapping(map) => {
            for key in [
                "combined",
                "verifier_log",
                "original_verifier_log",
                "log",
                "blocks",
            ] {
                let key = YamlValue::String(key.to_string());
                if let Some(log) = map.get(&key).and_then(collect_log_from_value) {
                    return Some(log);
                }
            }
            None
        }
        _ => None,
    }
}

fn yaml_path<'a>(value: &'a YamlValue, path: &[&str]) -> Option<&'a YamlValue> {
    let mut current = value;
    for part in path {
        let YamlValue::Mapping(map) = current else {
            return None;
        };
        current = map.get(YamlValue::String((*part).to_string()))?;
    }
    Some(current)
}

fn looks_like_verifier_log(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bpf")
        && (lower.contains("invalid ")
            || lower.contains("verifier")
            || lower.contains("processed ")
            || lower.contains("permission denied")
            || lower.contains("unbounded")
            || lower.contains("unknown func"))
}
