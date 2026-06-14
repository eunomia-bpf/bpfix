use std::path::{Path, PathBuf};

#[cfg(feature = "object-analysis")]
use anyhow::Context;
use anyhow::Result;
use clap::{Parser, ValueEnum};
use classifier::{classify, no_verifier_rejection_classification};
use diagnostic::{ProofEventEvidence, ProofEventRole};
use family::ProofObligation;
use input::{find_terminal_error, load_input, LoadedInput, TerminalError};
use output::{
    render_json, render_text, Diagnostic, Evidence, Metadata, ObjectProgramMetadata, RelatedSpan,
    SourceSpan,
};

mod classifier;
mod diagnostic;
mod family;
mod input;
mod output;
mod proof;
mod source;

#[derive(Parser, Debug)]
#[command(version, about = "Diagnose eBPF verifier failures from userspace")]
struct Cli {
    /// Verifier, build, bpftool, libbpf, Aya, or BCC log. Reads stdin when omitted or '-'.
    input: Option<PathBuf>,
    /// Experimental compiled BPF object metadata. Requires --features object-analysis.
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let loaded = load_input(cli.input.as_deref())?;
    let (object_path, object_programs, object_analysis_error) =
        object_metadata(cli.object.as_deref(), &loaded);
    let diagnostic = build_diagnostic(
        &loaded.log,
        cli.case_id,
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

fn object_metadata(
    explicit_object: Option<&Path>,
    loaded: &LoadedInput,
) -> (Option<String>, Vec<ObjectProgramMetadata>, Option<String>) {
    let Some(path) = explicit_object else {
        return (None, Vec::new(), None);
    };
    let object_path = path.display().to_string();

    #[cfg(feature = "object-analysis")]
    {
        return match validate_object_path(path)
            .and_then(|validated| load_object_program_metadata(Path::new(&validated), &loaded.log))
        {
            Ok(programs) => (Some(object_path), programs, None),
            Err(err) => (Some(object_path), Vec::new(), Some(err.to_string())),
        };
    }

    #[cfg(not(feature = "object-analysis"))]
    {
        let _ = loaded;
        (
            Some(object_path),
            Vec::new(),
            Some(
                "object analysis is disabled in this bpfix build; rebuild with --features object-analysis"
                    .to_string(),
            ),
        )
    }
}

#[cfg(feature = "object-analysis")]
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

#[cfg(feature = "object-analysis")]
fn validate_object_path(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to read object path {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("object path {} is not a file", path.display());
    }
    Ok(path.display().to_string())
}

fn build_diagnostic(
    log: &str,
    case_id: Option<String>,
    input_kind: &'static str,
    object_path: Option<String>,
    object_programs: Vec<ObjectProgramMetadata>,
    object_analysis_error: Option<String>,
) -> Diagnostic {
    let terminal = find_terminal_error(log);
    let class = terminal
        .as_ref()
        .map(|terminal| classify(&terminal.message))
        .unwrap_or_else(no_verifier_rejection_classification);
    let terminal = terminal.unwrap_or_else(|| TerminalError {
        line: log.lines().count().max(1),
        message: "no verifier rejection was found in this input".to_string(),
        pc: None,
        source_path: None,
        source_line: None,
        source_text: None,
    });
    let error_id = class.error_id.to_string();
    let (trace_state_count, analysis_error, proof_events, required_proof) =
        if class.error_id == "BPFIX-E000" {
            (0, None, Vec::new(), class.required_proof.to_string())
        } else {
            match diagnostic::analyze_verifier_log(
                log,
                terminal.pc,
                &terminal.message,
                class.obligation,
            ) {
                Ok(analysis) => {
                    let required_proof =
                        if analysis.required_proof.obligation == ProofObligation::Unknown {
                            class.required_proof.to_string()
                        } else {
                            analysis.required_proof.description
                        };
                    (analysis.state_count, None, analysis.events, required_proof)
                }
                Err(err) => (
                    0,
                    Some(err.to_string()),
                    Vec::new(),
                    class.required_proof.to_string(),
                ),
            }
        };
    let class_adjustment =
        classify_lowering_artifact(&terminal.message, class.failure_class, &proof_events);
    let failure_class = class_adjustment
        .map(|adjustment| adjustment.failure_class)
        .unwrap_or(class.failure_class)
        .to_string();
    let confidence = class_adjustment
        .map(|adjustment| adjustment.confidence)
        .unwrap_or(class.confidence)
        .to_string();
    let message_summary = class_adjustment
        .map(|adjustment| adjustment.summary)
        .unwrap_or(class.summary);

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
    if let Some(adjustment) = class_adjustment {
        evidence.push(Evidence {
            kind: "lowering_artifact_signal",
            detail: adjustment.evidence_detail.to_string(),
            line: Some(terminal.line),
        });
    }
    let rejected_detail = proof_events
        .iter()
        .find(|event| event.role == ProofEventRole::Rejected)
        .map(|event| event.detail.clone());
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
    let span_confidence = span_confidence(&source_span, &related_spans, &proof_events).to_string();

    let mut help = class
        .help
        .iter()
        .map(|item| (*item).to_string())
        .collect::<Vec<_>>();
    if let Some(adjustment) = class_adjustment {
        insert_help(&mut help, adjustment.help);
    }
    add_proof_event_help(&mut help, &proof_events);

    Diagnostic {
        diagnostic_version: "bpfix.diagnostic/v2",
        error_id: error_id.clone(),
        failure_class,
        confidence,
        diagnostic_kind: class.diagnostic_kind.to_string(),
        help_safety: class.help_safety.to_string(),
        span_confidence,
        message: format!("{}: {}", message_summary, terminal.message),
        required_proof,
        related_spans,
        source_span,
        evidence,
        help,
        primary_label: rejected_detail
            .unwrap_or_else(|| format!("rejected here: {}", class.summary)),
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

#[derive(Clone, Copy)]
struct ClassAdjustment {
    failure_class: &'static str,
    confidence: &'static str,
    summary: &'static str,
    evidence_detail: &'static str,
    help: &'static str,
}

fn classify_lowering_artifact(
    terminal_message: &str,
    base_failure_class: &str,
    proof_events: &[diagnostic::ProofEvent],
) -> Option<ClassAdjustment> {
    if base_failure_class != "source_bug" {
        return None;
    }

    let message = terminal_message.to_ascii_lowercase();
    if message.contains("misaligned stack access") {
        return Some(lowering_adjustment(
            "compiler-lowered stack access requires stronger alignment than the source layout exposes",
            "wide stack loads, stores, copies, or inline assembly can make stack-object alignment a verifier-visible property; align the stack object or avoid the wide access shape.",
        ));
    }
    if message.contains("same insn cannot be used with different pointers") {
        return Some(lowering_adjustment(
            "compiler code merging hides distinct pointer proofs from the verifier",
            "Keep incompatible pointer-typed paths separated at the dereference, or force the load to stay branch-local so one instruction is not shared by different verifier pointer types.",
        ));
    }
    if message.contains("pointer arithmetic with <<=") {
        return Some(lowering_adjustment(
            "compiler-lowered integer operation drops pointer provenance",
            "Keep packet or context pointers in verifier-tracked 64-bit pointer values; avoid materializing them through 32-bit scalar arithmetic before the access.",
        ));
    }
    if message.contains("dereference of modified ctx ptr") {
        return Some(lowering_adjustment(
            "compiler-lowered context access violates the verifier context contract",
            "Keep context field accesses as verifier-recognized field loads; avoid wide casts or modified context pointers for adjacent fields.",
        ));
    }
    if message.contains("expects pointer to ctx")
        && message.contains("caller passes invalid args into func")
    {
        return Some(lowering_adjustment(
            "compiler liveness hides the context argument required by a BPF subprogram",
            "Keep the context argument verifier-visible at the BPF-to-BPF callsite, for example by passing it directly or preventing the compiler from dropping the value.",
        ));
    }
    if proof_events.iter().any(|event| {
        event.role == ProofEventRole::ProofLost
            && event.evidence == ProofEventEvidence::VerifierState
            && event.obligation == ProofObligation::PointerProvenance
            && event.detail.contains("changes from pkt to scalar")
            && event
                .source
                .as_ref()
                .is_some_and(|source| source.text.contains("data_end"))
    }) {
        return Some(lowering_adjustment(
            "compiler-lowered control flow hides an established packet-pointer proof",
            "Keep the checked packet pointer derivation in the same verifier-visible path as the dereference, or rederive it from a checked base immediately before use.",
        ));
    }

    None
}

fn lowering_adjustment(evidence_detail: &'static str, help: &'static str) -> ClassAdjustment {
    ClassAdjustment {
        failure_class: "lowering_artifact",
        confidence: "medium",
        summary: "verifier-visible compiler lowering hides the required proof",
        evidence_detail,
        help,
    }
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
            Some((
                RelatedSpan {
                    path: source.path.clone(),
                    line_start: Some(source.line),
                    line_end: Some(source.line),
                    instruction_pc: event.pc,
                    source_text: Some(source.text.clone()),
                    label: related_span_label(event),
                },
                event.evidence,
            ))
        })
        .collect::<Vec<_>>();
    spans.sort_by_key(|(span, evidence)| {
        (
            span.line_start.unwrap_or(usize::MAX),
            evidence_strength_rank(*evidence),
        )
    });
    spans.dedup_by(|(left, _), (right, _)| {
        left.path == right.path && left.line_start == right.line_start
    });
    spans.into_iter().map(|(span, _)| span).collect()
}

fn related_span_label(event: &diagnostic::ProofEvent) -> String {
    if event.evidence == ProofEventEvidence::SourceComment {
        return format!(
            "nearby source context for {}",
            event.obligation.context_label()
        );
    }
    event.detail.clone()
}

fn evidence_strength_rank(evidence: ProofEventEvidence) -> u8 {
    match evidence {
        ProofEventEvidence::VerifierState | ProofEventEvidence::TerminalVerifier => 0,
        ProofEventEvidence::SourceComment => 1,
    }
}

fn add_proof_event_help(help: &mut Vec<String>, events: &[diagnostic::ProofEvent]) {
    for event in events {
        if event.role != ProofEventRole::ProofLost {
            continue;
        }
        if event.evidence != ProofEventEvidence::VerifierState {
            continue;
        }
        if event.obligation == ProofObligation::PointerProvenance {
            insert_help(
                help,
                "Preserve pointer provenance across the failing path, or rederive the pointer from a checked base immediately before dereferencing it.",
            );
        }
    }
}

fn span_confidence(
    source_span: &SourceSpan,
    related_spans: &[RelatedSpan],
    proof_events: &[diagnostic::ProofEvent],
) -> &'static str {
    let has_non_source_comment_pc = proof_events
        .iter()
        .any(|event| event.pc.is_some() && event.evidence != ProofEventEvidence::SourceComment);
    if source_span.instruction_pc.is_some() && has_non_source_comment_pc {
        return "exact_pc";
    }
    if !related_spans.is_empty() || source_span.source_text.is_some() {
        return "nearest_source_comment";
    }
    if source_span.line_start.is_some() {
        return "terminal_line_only";
    }
    "none"
}

fn insert_help(help: &mut Vec<String>, item: &str) {
    if help.iter().any(|existing| existing == item) {
        return;
    }
    help.insert(0, item.to_string());
}
