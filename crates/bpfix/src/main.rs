use std::path::{Path, PathBuf};

#[cfg(feature = "object-analysis")]
use anyhow::Context;
use anyhow::Result;
use clap::{Parser, ValueEnum};
use classifier::{classify_with_context, no_verifier_rejection_classification};
use diagnostic::{ProofEventEvidence, ProofEventRole, ProofSignal};
use family::ProofObligation;
use input::{find_terminal_error, load_input, LoadedInput, TerminalError};
use output::{
    render_json, render_text, Diagnostic, Evidence, Metadata, NextAction, ObjectProgramMetadata,
    RelatedSpan, SourceSpan,
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
    /// Exit with code 2 after rendering if the input cannot be diagnosed.
    #[arg(long)]
    fail_on_unsupported: bool,
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
        &loaded.full_log,
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

    if cli.fail_on_unsupported && diagnostic.diagnostic_kind != "supported" {
        std::process::exit(2);
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
        match validate_object_path(path)
            .and_then(|validated| load_object_program_metadata(Path::new(&validated), &loaded.log))
        {
            Ok(programs) => (Some(object_path), programs, None),
            Err(err) => (Some(object_path), Vec::new(), Some(err.to_string())),
        }
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
    full_log: &str,
    case_id: Option<String>,
    input_kind: &'static str,
    object_path: Option<String>,
    object_programs: Vec<ObjectProgramMetadata>,
    object_analysis_error: Option<String>,
) -> Diagnostic {
    let terminal = find_terminal_error(log);
    let class = terminal
        .as_ref()
        .map(|terminal| classify_with_context(&terminal.message, terminal.call_target.as_deref()))
        .unwrap_or_else(no_verifier_rejection_classification);
    let terminal = terminal.unwrap_or_else(|| TerminalError {
        line: log.lines().count().max(1),
        message: "no verifier rejection was found in this input".to_string(),
        pc: None,
        call_target: None,
        source_path: None,
        source_line: None,
        source_text: None,
    });
    let (trace_state_count, analysis_error, proof_events, proof_signals, required_proof) =
        if class.error_id == "BPFIX-E000" {
            (
                0,
                None,
                Vec::new(),
                Vec::new(),
                class.required_proof.to_string(),
            )
        } else {
            match diagnostic::analyze_verifier_log_with_context(
                log,
                full_log,
                terminal.pc,
                Some(terminal.line),
                &terminal.message,
                terminal.call_target.as_deref(),
                class.obligation,
            ) {
                Ok(analysis) => {
                    let required_proof =
                        if analysis.required_proof.obligation == ProofObligation::Unknown {
                            class.required_proof.to_string()
                        } else {
                            analysis.required_proof.description
                        };
                    (
                        analysis.state_count,
                        None,
                        analysis.events,
                        analysis.signals,
                        required_proof,
                    )
                }
                Err(err) => (
                    0,
                    Some(err.to_string()),
                    Vec::new(),
                    Vec::new(),
                    class.required_proof.to_string(),
                ),
            }
        };
    let proof_signal = runtime_proof_signal(class.failure_class, &proof_signals);
    let error_id = proof_signal
        .and_then(ProofSignal::error_id_override)
        .unwrap_or(class.error_id)
        .to_string();
    let failure_class = proof_signal
        .map(ProofSignal::failure_class)
        .unwrap_or(class.failure_class)
        .to_string();
    let confidence = proof_signal
        .map(ProofSignal::confidence)
        .unwrap_or(class.confidence)
        .to_string();
    let message_summary = proof_signal
        .map(ProofSignal::summary)
        .unwrap_or(class.summary);
    let help_safety = proof_signal
        .map(ProofSignal::help_safety)
        .unwrap_or(class.help_safety)
        .to_string();
    let next_action = proof_signal
        .map(ProofSignal::next_action)
        .unwrap_or_else(|| classifier_next_action(&class));
    let diagnostic_kind = if class.diagnostic_kind == "unsupported_verifier_message"
        && proof_signal.is_some_and(ProofSignal::can_replace_unsupported_terminal)
    {
        "supported"
    } else {
        class.diagnostic_kind
    };
    let required_proof = proof_signal
        .and_then(ProofSignal::required_proof_override)
        .map(ToOwned::to_owned)
        .unwrap_or(required_proof);

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
    if let Some(signal) = proof_signal {
        evidence.push(Evidence {
            kind: signal.evidence_kind(),
            detail: signal.evidence_detail().to_string(),
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

    let mut help = if proof_signal.is_some_and(ProofSignal::replaces_classifier_help) {
        Vec::new()
    } else {
        class
            .help
            .iter()
            .map(|item| (*item).to_string())
            .collect::<Vec<_>>()
    };
    if let Some(signal) = proof_signal {
        insert_help(&mut help, signal.help());
    }
    add_proof_event_help(&mut help, &proof_events);

    Diagnostic {
        diagnostic_version: "bpfix.diagnostic/v3",
        error_id: error_id.clone(),
        failure_class,
        confidence,
        diagnostic_kind: diagnostic_kind.to_string(),
        help_safety,
        next_action,
        span_confidence,
        message: format!("{}: {}", message_summary, terminal.message),
        required_proof,
        related_spans,
        source_span,
        evidence,
        help,
        primary_label: proof_signal
            .and_then(ProofSignal::primary_label_override)
            .map(ToOwned::to_owned)
            .or(rejected_detail)
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

fn classifier_next_action(class: &classifier::Classification) -> NextAction {
    match class.failure_class {
        "environment_or_configuration" => NextAction::Environment,
        "verifier_limit" => NextAction::Budget,
        "input_error" | "unsupported_verifier_message" => NextAction::Other,
        _ => obligation_next_action(class.obligation),
    }
}

fn obligation_next_action(obligation: ProofObligation) -> NextAction {
    match obligation {
        ProofObligation::PacketBounds | ProofObligation::ScalarRange => NextAction::Bounds,
        ProofObligation::NullablePointer => NextAction::Null,
        ProofObligation::StackInitialized => NextAction::Initialize,
        ProofObligation::ReferenceLifecycle => NextAction::Release,
        ProofObligation::VerifierLimit | ProofObligation::LoopBound => NextAction::Budget,
        ProofObligation::EnvironmentCapability | ProofObligation::InstructionSupport => {
            NextAction::Environment
        }
        ProofObligation::PointerProvenance
        | ProofObligation::Alignment
        | ProofObligation::TypeContract => NextAction::Provenance,
        ProofObligation::ContextAccess => NextAction::Context,
        ProofObligation::HelperArgument
        | ProofObligation::DynptrSafety
        | ProofObligation::KfuncReference
        | ProofObligation::IteratorLifecycle
        | ProofObligation::LockState => NextAction::Protocol,
        ProofObligation::Unknown => NextAction::Other,
    }
}

fn runtime_proof_signal(
    base_failure_class: &str,
    proof_signals: &[ProofSignal],
) -> Option<ProofSignal> {
    proof_signals
        .iter()
        .copied()
        .find(|signal| signal.can_override_base_failure_class(base_failure_class))
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
        if event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::VerifierState
            && event.obligation == ProofObligation::PacketBounds
        {
            insert_help(
                help,
                "Use the packet pointer derivation that received the data_end proof, or rederive and recheck the final access pointer immediately before the load.",
            );
        }
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
