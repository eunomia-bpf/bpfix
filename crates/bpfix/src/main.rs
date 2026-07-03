use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(feature = "object-analysis")]
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use classifier::{classify_with_context, no_verifier_rejection_classification};
use diagnostic::{ProofEventEvidence, ProofEventRole, ProofSignal};
use family::ProofObligation;
use input::{find_terminal_error, load_input, LoadedInput, TerminalError};
use output::{
    render_text, Diagnostic, Evidence, Metadata, NextAction, ObjectProgramMetadata, RelatedSpan,
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
    /// Check local tools used for replay, object metadata, and verifier-oracle workflows.
    #[arg(long)]
    doctor: bool,
    /// Exit with code 2 after rendering if the input cannot be diagnosed.
    #[arg(long)]
    fail_on_unsupported: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.doctor {
        if cli.input.is_some() || cli.object.is_some() || cli.fail_on_unsupported {
            anyhow::bail!("--doctor does not take a log input, --object, or --fail-on-unsupported");
        }
        print!("{}", render_doctor());
        return Ok(());
    }

    let loaded = load_input(cli.input.as_deref())?;
    let (object_programs, object_analysis_error) = object_metadata(cli.object.as_deref(), &loaded);
    let diagnostic = build_diagnostic(
        &loaded.log,
        &loaded.full_log,
        object_programs,
        object_analysis_error,
    );

    print!("{}", render_text(&diagnostic));

    if cli.fail_on_unsupported && diagnostic.diagnostic_kind != "supported" {
        std::process::exit(2);
    }

    Ok(())
}

fn render_doctor() -> String {
    let mut out = String::new();
    out.push_str("bpfix doctor\n");
    out.push_str(&format!("version: {}\n", env!("CARGO_PKG_VERSION")));
    out.push_str("log-only diagnostics: ok (use `bpfix LOG`, `bpfix -`, or pipe stdin)\n");
    out.push_str("\nlocal environment:\n");

    push_check(
        &mut out,
        "object-analysis feature",
        cfg!(feature = "object-analysis"),
        if cfg!(feature = "object-analysis") {
            "enabled; --object can attach compiled-object metadata"
        } else {
            "disabled; rebuild with `--features object-analysis` to enrich --object diagnostics"
        },
    );
    push_command_check(
        &mut out,
        "clang",
        "clang",
        &["--version"],
        "required to rebuild BPF C sources",
    );
    push_command_check(
        &mut out,
        "bpftool",
        "bpftool",
        &["version"],
        "required to load programs and capture verifier logs",
    );
    push_command_check(
        &mut out,
        "llvm-objdump",
        "llvm-objdump",
        &["--version"],
        "useful for object inspection and fixture debugging",
    );
    push_path_check(
        &mut out,
        "kernel BTF",
        Path::new("/sys/kernel/btf/vmlinux"),
        "required by many CO-RE and bpftool load workflows",
    );
    push_sudo_check(&mut out);
    out.push_str("\nnotes:\n");
    out.push_str("- Missing replay/load tools do not block plain log diagnostics.\n");
    out.push_str("- They matter when rebuilding BPF programs, loading through the kernel verifier, or running bpfix-bench oracles.\n");
    out
}

fn push_check(out: &mut String, name: &str, ok: bool, detail: &str) {
    let status = if ok { "ok" } else { "warn" };
    out.push_str(&format!("  {status}: {name}: {detail}\n"));
}

fn push_path_check(out: &mut String, name: &str, path: &Path, detail: &str) {
    let status = if path.is_file() { "ok" } else { "warn" };
    let suffix = if path.is_file() { detail } else { "not found" };
    out.push_str(&format!(
        "  {status}: {name}: {} ({suffix})\n",
        path.display()
    ));
}

fn push_command_check(out: &mut String, name: &str, program: &str, args: &[&str], detail: &str) {
    match command_first_line(program, args) {
        Some(line) => out.push_str(&format!("  ok: {name}: {line}\n")),
        None => out.push_str(&format!(
            "  warn: {name}: not found or not runnable ({detail})\n"
        )),
    }
}

fn command_first_line(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
}

fn push_sudo_check(out: &mut String) {
    match Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => {
            out.push_str(
                "  ok: sudo -n true: non-interactive sudo is available for load/replay workflows\n",
            );
        }
        Ok(_) => {
            out.push_str("  warn: sudo -n true: unavailable without a password; log-only diagnostics still work\n");
        }
        Err(_) => {
            out.push_str("  warn: sudo: not found; log-only diagnostics still work\n");
        }
    }
}

fn object_metadata(
    explicit_object: Option<&Path>,
    loaded: &LoadedInput,
) -> (Vec<ObjectProgramMetadata>, Option<String>) {
    if explicit_object.is_none() {
        return (Vec::new(), None);
    }

    #[cfg(feature = "object-analysis")]
    {
        let path = explicit_object.expect("checked above");
        match validate_object_path(path)
            .and_then(|validated| load_object_program_metadata(Path::new(&validated), &loaded.log))
        {
            Ok(programs) => (programs, None),
            Err(err) => (Vec::new(), Some(err.to_string())),
        }
    }

    #[cfg(not(feature = "object-analysis"))]
    {
        let _ = explicit_object;
        let _ = loaded;
        (
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
    object_programs: Vec<ObjectProgramMetadata>,
    object_analysis_error: Option<String>,
) -> Diagnostic {
    let object_sections = active_object_sections(&object_programs);
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
            match diagnostic::analyze_verifier_log_with_context(diagnostic::VerifierLogContext {
                log,
                full_log,
                object_sections: &object_sections,
                terminal_pc: terminal.pc,
                terminal_line: Some(terminal.line),
                terminal_error: &terminal.message,
                terminal_call_target: terminal.call_target.as_deref(),
                obligation: class.obligation,
            }) {
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
            object_analysis_error,
            trace_state_count,
            analysis_error,
        },
    }
}

fn active_object_sections(object_programs: &[ObjectProgramMetadata]) -> Vec<String> {
    let sections = object_programs
        .iter()
        .filter(|program| {
            program.verifier_state_site_count > 0 && program.verifier_state_attach_error.is_none()
        })
        .map(|program| program.section_name.clone())
        .collect::<Vec<_>>();
    if sections.len() == 1 {
        sections
    } else {
        Vec::new()
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
                "Reacquire a verifier-tracked pointer before the rejected dereference.",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn object_program(
        section_name: &str,
        verifier_state_site_count: usize,
    ) -> ObjectProgramMetadata {
        ObjectProgramMetadata {
            section_name: section_name.to_string(),
            verifier_state_site_count,
            verifier_state_attach_error: None,
        }
    }

    #[test]
    fn active_object_sections_selects_only_rejected_program() {
        let programs = [
            object_program("xdp", 0),
            object_program("tracepoint/skb/consume_skb", 6),
        ];
        assert_eq!(
            active_object_sections(&programs),
            vec!["tracepoint/skb/consume_skb".to_string()]
        );
    }

    #[test]
    fn active_object_sections_rejects_ambiguous_active_programs() {
        let programs = [
            object_program("xdp", 4),
            object_program("tracepoint/skb/x", 6),
        ];
        assert!(active_object_sections(&programs).is_empty());
    }
}
