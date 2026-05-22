use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use diagnostic::ProofEventRole;
use serde::Serialize;
use serde_yaml::Value as YamlValue;

mod diagnostic;

#[derive(Parser, Debug)]
#[command(version, about = "Diagnose eBPF verifier failures from userspace")]
struct Cli {
    /// Verifier log or bpfix-bench raw YAML. Reads stdin when omitted or '-'.
    input: Option<PathBuf>,
    /// Optional compiled BPF object. Used for validation now and source/BTF correlation later.
    #[arg(long)]
    object: Option<PathBuf>,
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
    object_path_hint: Option<String>,
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

#[derive(Clone, Debug)]
struct Classification {
    error_id: &'static str,
    failure_class: &'static str,
    summary: &'static str,
    required_proof: &'static str,
    repairs: &'static [&'static str],
}

#[derive(Serialize)]
struct Diagnostic {
    diagnostic_version: &'static str,
    error_id: String,
    failure_class: String,
    message: String,
    required_proof: String,
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
    object_path: Option<String>,
    object_programs: Vec<ObjectProgramMetadata>,
    object_analysis_error: Option<String>,
    trace_state_count: usize,
    analysis_error: Option<String>,
}

#[derive(Serialize)]
struct ObjectProgramMetadata {
    section_name: String,
    instruction_count: usize,
    block_count: usize,
    site_count: usize,
    verifier_state_site_count: usize,
    verifier_state_attach_error: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let loaded = load_input(cli.input.as_deref())?;
    let (object_path, object_programs, object_analysis_error) =
        object_metadata(cli.object.as_deref(), &loaded);
    let case_id = cli.case_id.or_else(|| loaded.case_id.clone());
    let diagnostic = build_diagnostic(
        &loaded.log,
        case_id,
        loaded.input_kind,
        object_path,
        object_programs,
        object_analysis_error,
    );

    match cli.format {
        OutputFormat::Text => println!("{}", render_text(&diagnostic)),
        OutputFormat::Json => println!("{}", render_json(&diagnostic)?),
        OutputFormat::Both => {
            println!("{}", render_text(&diagnostic));
            println!();
            println!("{}", render_json(&diagnostic)?);
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
    let object_path_hint = detect_object_path(&raw);
    if let Ok(yaml) = serde_yaml::from_str::<YamlValue>(&raw) {
        if let Some(log) = extract_verifier_log(&yaml) {
            let (log, input_kind) = normalize_verifier_log(log, "bpfix-bench-yaml");
            return Ok(LoadedInput {
                log,
                case_id: extract_case_id(&yaml),
                input_kind,
                object_path_hint,
            });
        }
    }

    let (log, input_kind) = normalize_verifier_log(raw, "verifier-log");
    Ok(LoadedInput {
        log,
        case_id: path
            .and_then(Path::file_stem)
            .and_then(|stem| stem.to_str())
            .map(ToOwned::to_owned),
        input_kind,
        object_path_hint,
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

fn object_metadata(
    explicit_object: Option<&Path>,
    loaded: &LoadedInput,
) -> (Option<String>, Vec<ObjectProgramMetadata>, Option<String>) {
    match explicit_object {
        Some(path) => {
            let object_path = path.display().to_string();
            match validate_object_path(path).and_then(|validated| {
                load_object_program_metadata(Path::new(&validated), &loaded.log)
            }) {
                Ok(programs) => (Some(object_path), programs, None),
                Err(err) => (Some(object_path), Vec::new(), Some(err.to_string())),
            }
        }
        None => {
            let Some(path) = loaded.object_path_hint.as_deref() else {
                return (None, Vec::new(), None);
            };
            let object_path = Path::new(path);
            if !object_path.is_file() {
                return (Some(path.to_string()), Vec::new(), None);
            }
            match load_object_program_metadata(object_path, &loaded.log) {
                Ok(programs) => (Some(path.to_string()), programs, None),
                Err(err) => (Some(path.to_string()), Vec::new(), Some(err.to_string())),
            }
        }
    }
}

fn load_object_program_metadata(path: &Path, log: &str) -> Result<Vec<ObjectProgramMetadata>> {
    let summaries = bpfanalysis::load_object_cfg_summaries(path, Some(log))?;
    Ok(summaries
        .into_iter()
        .map(|summary| ObjectProgramMetadata {
            section_name: summary.section_name,
            instruction_count: summary.instruction_count,
            block_count: summary.block_count,
            site_count: summary.site_count,
            verifier_state_site_count: summary.verifier_state_site_count,
            verifier_state_attach_error: summary.verifier_state_attach_error,
        })
        .collect())
}

fn validate_object_path(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to read object path {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("object path {} is not a file", path.display());
    }
    Ok(path.display().to_string())
}

fn normalize_verifier_log(raw: String, base_kind: &'static str) -> (String, &'static str) {
    match extract_verifier_log_region(&raw) {
        Some(region) => {
            let kind = match base_kind {
                "bpfix-bench-yaml" => "bpfix-bench-yaml-region",
                _ => "verifier-log-region",
            };
            (region, kind)
        }
        None => (raw, base_kind),
    }
}

fn extract_verifier_log_region(raw: &str) -> Option<String> {
    let lines = raw.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }

    if let Some(begin) = lines
        .iter()
        .position(|line| line.contains("-- BEGIN PROG LOAD LOG --"))
    {
        let end = lines
            .iter()
            .enumerate()
            .skip(begin + 1)
            .find_map(|(idx, line)| line.contains("-- END PROG LOAD LOG --").then_some(idx))
            .unwrap_or(lines.len());
        if begin + 1 < end {
            return Some(join_lines(&lines[begin + 1..end]));
        }
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

fn detect_object_path(raw: &str) -> Option<String> {
    raw.lines().find_map(|line| {
        line.trim()
            .strip_prefix("libbpf: loading object from ")
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
    })
}

fn build_diagnostic(
    log: &str,
    case_id: Option<String>,
    input_kind: &'static str,
    object_path: Option<String>,
    object_programs: Vec<ObjectProgramMetadata>,
    object_analysis_error: Option<String>,
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
    let error_id = class.error_id.to_string();
    let (trace_state_count, analysis_error, proof_events) =
        match diagnostic::analyze_verifier_log(log, terminal.pc, &terminal.message) {
            Ok(analysis) => (analysis.state_count, None, analysis.events),
            Err(err) => (0, Some(err.to_string()), Vec::new()),
        };
    let failure_class = inferred_failure_class(&class, &proof_events).to_string();

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
    let source_span = proof_events
        .iter()
        .find(|event| event.role == ProofEventRole::Rejected)
        .and_then(source_span_from_proof_event)
        .unwrap_or_else(|| SourceSpan {
            path: terminal
                .source_path
                .clone()
                .unwrap_or_else(|| "<verifier-log>".to_string()),
            line_start: terminal.source_line.or(Some(terminal.line)),
            line_end: terminal.source_line.or(Some(terminal.line)),
            instruction_pc: terminal.pc,
            source_text: terminal.source_text.clone(),
        });
    let related_spans = related_spans_from_proof_events(&proof_events);

    let mut candidate_repairs = class
        .repairs
        .iter()
        .map(|repair| (*repair).to_string())
        .collect::<Vec<_>>();
    add_proof_event_repairs(&mut candidate_repairs, &proof_events);

    Diagnostic {
        diagnostic_version: "bpfix.diagnostic/v1",
        error_id: error_id.clone(),
        failure_class,
        message: format!("{}: {}", class.summary, terminal.message),
        required_proof: class.required_proof.to_string(),
        related_spans,
        source_span,
        evidence,
        candidate_repairs,
        metadata: Metadata {
            case_id,
            input_kind,
            object_path,
            object_programs,
            object_analysis_error,
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

fn source_span_from_proof_event(event: &diagnostic::ProofEvent) -> Option<SourceSpan> {
    let source = event.source.as_ref()?;
    Some(SourceSpan {
        path: source.path.clone(),
        line_start: Some(source.line),
        line_end: Some(source.line),
        instruction_pc: event.pc,
        source_text: Some(source.text.clone()),
    })
}

fn related_spans_from_proof_events(events: &[diagnostic::ProofEvent]) -> Vec<RelatedSpan> {
    let mut spans = events
        .iter()
        .filter(|event| event.role != ProofEventRole::Rejected)
        .filter_map(|event| {
            let source = event.source.as_ref()?;
            Some(RelatedSpan {
                path: source.path.clone(),
                line_start: Some(source.line),
                line_end: Some(source.line),
                instruction_pc: event.pc,
                source_text: Some(source.text.clone()),
                label: event.detail.clone(),
            })
        })
        .collect::<Vec<_>>();
    spans.sort_by_key(|span| span.line_start.unwrap_or(usize::MAX));
    spans.dedup_by(|left, right| left.path == right.path && left.line_start == right.line_start);
    spans
}

fn add_proof_event_repairs(repairs: &mut Vec<String>, events: &[diagnostic::ProofEvent]) {
    for event in events {
        if event.role != ProofEventRole::ProofLost {
            continue;
        }
        if event.detail.contains("branch-specific pointers") {
            insert_repair(
                repairs,
                "Keep branch-specific pointer derivations in separate verifier-visible branches, or rederive the pointer from a checked base immediately before dereferencing it.",
            );
        }
    }
}

fn insert_repair(repairs: &mut Vec<String>, repair: &str) {
    if repairs.iter().any(|existing| existing == repair) {
        return;
    }
    repairs.insert(0, repair.to_string());
}

fn inferred_failure_class(
    class: &Classification,
    proof_events: &[diagnostic::ProofEvent],
) -> &'static str {
    if proof_events
        .iter()
        .any(|event| event.role == ProofEventRole::ProofLost)
    {
        return "lowering_artifact";
    }
    match class.error_id {
        "BPFIX-E005" | "BPFIX-E006" => "source_bug",
        _ => class.failure_class,
    }
}

fn classify(message: &str) -> Classification {
    let lower = message.to_ascii_lowercase();
    if lower.contains("invalid access to packet") || lower.contains("outside of the packet") {
        return Classification {
            error_id: "BPFIX-E001",
            failure_class: "source_bug",
            summary: "packet bounds proof is missing",
            required_proof: "prove that the packet pointer plus requested access size stays before data_end on every path reaching the load, store, or helper call",
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
            required_proof: "prove that the nullable pointer returned by a helper is checked for null before dereference or helper reuse",
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
            required_proof: "initialize every stack byte that can be read directly or passed indirectly to a helper",
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
            required_proof: "release every acquired verifier-tracked reference on every exit path",
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
            required_proof: "bound the scalar value tightly enough for the verifier to prove the memory access range",
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
            required_proof: "preserve a verifier-recognized pointer type at the operation that requires a pointer",
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
            required_proof: "reduce verifier state growth or provide a statically bounded loop shape",
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
            required_proof: "load the program with a kernel, program type, attach point, and privileges that support the requested helper or kfunc",
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
            required_proof: "keep dynptr slices inside their proven lifetime, initialized range, and read/write mode",
            repairs: &[
                "Revalidate dynptr slice nullability and length before use.",
                "Do not reuse a dynptr slice after an operation that invalidates it.",
            ],
        };
    }
    Classification {
        error_id: "BPFIX-UNKNOWN",
        failure_class: "source_bug",
        summary: "required verifier proof is not classified yet",
        required_proof: "inspect the terminal verifier line and add the missing safety proof required at that program point",
        repairs: &[
            "Move the relevant check closer to the rejected instruction.",
            "Preserve the exact register or scalar value that the verifier has already proven safe.",
        ],
    }
}

fn render_json(diagnostic: &Diagnostic) -> Result<String> {
    serde_json::to_string_pretty(diagnostic).context("failed to render diagnostic JSON")
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
        "   = required proof: {}\n",
        diagnostic.required_proof
    ));
    if let Some(err) = &diagnostic.metadata.analysis_error {
        out.push_str(&format!("   = warning: {err}\n"));
    }
    if let Some(err) = &diagnostic.metadata.object_analysis_error {
        out.push_str(&format!("   = warning: object analysis: {err}\n"));
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
        _ => "required verifier proof is missing here",
    }
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
