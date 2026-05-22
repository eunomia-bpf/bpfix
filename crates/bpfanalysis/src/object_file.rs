use std::path::Path;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, SectionKind};

use crate::analysis::{lift_with_pass_context, ProgramCFG};
use crate::insn::BpfInsn;
use crate::pass::PassContext;
use crate::verifier_log::{verifier_states_from_log, VerifierInsn};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectProgramSummary {
    pub section_name: String,
    pub instruction_count: usize,
    pub block_count: usize,
    pub site_count: usize,
    pub verifier_state_site_count: usize,
    pub verifier_state_attach_error: Option<String>,
}

pub fn load_object_cfg_summaries(
    path: &Path,
    verifier_log: Option<&str>,
) -> Result<Vec<ObjectProgramSummary>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read BPF object {}", path.display()))?;
    let file = object::File::parse(bytes.as_slice())
        .with_context(|| format!("failed to parse ELF object {}", path.display()))?;
    let mut summaries = Vec::new();
    let (verifier_states, verifier_state_parse_error) = parse_verifier_states(verifier_log);

    for section in file.sections() {
        if !is_program_section(&section) {
            continue;
        }
        let name = section.name().unwrap_or("<unnamed>").to_string();
        let data = section
            .data()
            .with_context(|| format!("failed to read section {name}"))?;
        let insns = decode_bpf_insns(data).with_context(|| {
            format!(
                "failed to decode section {name} as BPF instructions in {}",
                path.display()
            )
        })?;
        if insns.is_empty() {
            continue;
        }

        let (cfg, verifier_state_attach_error) = lift_program_cfg(
            &insns,
            verifier_states.as_deref(),
            verifier_state_parse_error.as_deref(),
        )
        .with_context(|| format!("failed to lift section {name} into ProgramCFG"))?;
        let site_count = cfg.all_sites().count();
        let verifier_state_site_count =
            verifier_state_site_count(&cfg, verifier_state_attach_error.is_none());
        summaries.push(ObjectProgramSummary {
            section_name: name,
            instruction_count: insns.len(),
            block_count: cfg.blocks().count(),
            site_count,
            verifier_state_site_count,
            verifier_state_attach_error,
        });
    }

    mark_ambiguous_state_attachments(&mut summaries);
    Ok(summaries)
}

fn mark_ambiguous_state_attachments(summaries: &mut [ObjectProgramSummary]) {
    let attached_count = summaries
        .iter()
        .filter(|summary| {
            summary.verifier_state_site_count > 0 && summary.verifier_state_attach_error.is_none()
        })
        .count();
    if attached_count <= 1 {
        return;
    }

    for summary in summaries {
        if summary.verifier_state_site_count == 0 || summary.verifier_state_attach_error.is_some() {
            continue;
        }
        summary.verifier_state_attach_error = Some(
            "verifier states match multiple object sections; CFG correlation is ambiguous without a loaded-program section match"
                .to_string(),
        );
        summary.verifier_state_site_count = 0;
    }
}

fn parse_verifier_states(
    verifier_log: Option<&str>,
) -> (Option<Vec<VerifierInsn>>, Option<String>) {
    let Some(log) = verifier_log else {
        return (None, None);
    };
    match verifier_states_from_log(log) {
        Ok(states) => (Some(states), None),
        Err(err) => (None, Some(err.to_string())),
    }
}

fn lift_program_cfg(
    insns: &[BpfInsn],
    verifier_states: Option<&[VerifierInsn]>,
    verifier_state_parse_error: Option<&str>,
) -> Result<(ProgramCFG, Option<String>)> {
    let Some(states) = verifier_states.filter(|states| !states.is_empty()) else {
        return Ok((
            lift_without_verifier_states(insns)?,
            verifier_state_parse_error.map(ToOwned::to_owned),
        ));
    };

    let mut ctx = PassContext::default();
    ctx.set_verifier_states(states.to_vec());
    match lift_with_pass_context(insns, &ctx) {
        Ok(cfg) => Ok((cfg, None)),
        Err(err) => Ok((
            lift_without_verifier_states(insns)?,
            Some(format!(
                "verifier states could not be attached to this section CFG: {err:#}"
            )),
        )),
    }
}

fn lift_without_verifier_states(insns: &[BpfInsn]) -> Result<ProgramCFG> {
    lift_with_pass_context(insns, &PassContext::default())
}

fn verifier_state_site_count(cfg: &ProgramCFG, states_attached: bool) -> usize {
    if !states_attached {
        return 0;
    }
    cfg.all_sites()
        .filter(|site| cfg.verifier_states_at(*site).is_some())
        .count()
}

fn is_program_section(section: &object::Section<'_, '_>) -> bool {
    let Ok(name) = section.name() else {
        return false;
    };
    if name.starts_with('.')
        || matches!(name, "license" | "maps" | "version")
        || name.starts_with("license")
    {
        return false;
    }
    if section.kind() == SectionKind::Text {
        return true;
    }
    section.size() > 0 && section.size() % 8 == 0
}

fn decode_bpf_insns(data: &[u8]) -> Result<Vec<BpfInsn>> {
    if data.len() % 8 != 0 {
        anyhow::bail!(
            "BPF instruction section length {} is not a multiple of 8",
            data.len()
        );
    }
    Ok(data
        .chunks_exact(8)
        .map(|chunk| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(chunk);
            BpfInsn::from_raw_bytes(raw)
        })
        .collect())
}
