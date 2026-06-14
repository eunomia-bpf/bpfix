use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Diagnostic {
    pub(crate) diagnostic_version: &'static str,
    pub(crate) error_id: String,
    pub(crate) failure_class: String,
    pub(crate) confidence: String,
    pub(crate) diagnostic_kind: String,
    pub(crate) help_safety: String,
    pub(crate) span_confidence: String,
    pub(crate) message: String,
    pub(crate) required_proof: String,
    pub(crate) source_span: SourceSpan,
    pub(crate) related_spans: Vec<RelatedSpan>,
    pub(crate) evidence: Vec<Evidence>,
    pub(crate) help: Vec<String>,
    pub(crate) metadata: Metadata,
    #[serde(skip)]
    pub(crate) primary_label: String,
}

#[derive(Serialize)]
pub(crate) struct SourceSpan {
    pub(crate) path: String,
    pub(crate) line_start: Option<usize>,
    pub(crate) line_end: Option<usize>,
    pub(crate) instruction_pc: Option<usize>,
    pub(crate) source_text: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct RelatedSpan {
    pub(crate) path: String,
    pub(crate) line_start: Option<usize>,
    pub(crate) line_end: Option<usize>,
    pub(crate) instruction_pc: Option<usize>,
    pub(crate) source_text: Option<String>,
    pub(crate) label: String,
}

#[derive(Serialize)]
pub(crate) struct Evidence {
    pub(crate) kind: &'static str,
    pub(crate) detail: String,
    pub(crate) line: Option<usize>,
}

#[derive(Serialize)]
pub(crate) struct Metadata {
    pub(crate) case_id: Option<String>,
    pub(crate) input_kind: &'static str,
    pub(crate) object_path: Option<String>,
    pub(crate) object_programs: Vec<ObjectProgramMetadata>,
    pub(crate) object_analysis_error: Option<String>,
    pub(crate) trace_state_count: usize,
    pub(crate) analysis_error: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ObjectProgramMetadata {
    pub(crate) section_name: String,
    pub(crate) instruction_count: usize,
    pub(crate) block_count: usize,
    pub(crate) site_count: usize,
    pub(crate) verifier_state_site_count: usize,
    pub(crate) verifier_state_attach_error: Option<String>,
}

pub(crate) fn render_json(diagnostic: &Diagnostic) -> Result<String> {
    serde_json::to_string_pretty(diagnostic).context("failed to render diagnostic JSON")
}

pub(crate) fn render_text(diagnostic: &Diagnostic) -> String {
    let mut out = String::new();
    let title = diagnostic
        .message
        .split_once(':')
        .map(|(title, _)| title)
        .unwrap_or(&diagnostic.message);
    out.push_str(&format!("error[{}]: {title}\n", diagnostic.error_id));
    out.push_str(&format!("  = class: {}\n", diagnostic.failure_class));
    out.push_str(&format!("  = confidence: {}\n", diagnostic.confidence));
    out.push_str(&format!(
        "  = diagnostic: {}, help: {}, span: {}\n",
        diagnostic.diagnostic_kind, diagnostic.help_safety, diagnostic.span_confidence
    ));

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
    render_runtime_evidence_notes(&mut out, diagnostic);
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
    for item in &diagnostic.help {
        out.push_str(&format!("help: {item}\n"));
    }
    out
}

fn render_runtime_evidence_notes(out: &mut String, diagnostic: &Diagnostic) {
    for evidence in &diagnostic.evidence {
        let Some(label) = runtime_evidence_label(evidence.kind) else {
            continue;
        };
        out.push_str(&format!("   = note[{label}]: {}\n", evidence.detail));
    }
}

fn runtime_evidence_label(kind: &str) -> Option<&'static str> {
    match kind {
        "lowering_artifact_signal" => Some("lowering"),
        "verifier_precision_signal" => Some("verifier-precision"),
        _ => None,
    }
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
            label: diagnostic.primary_label.as_str(),
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
