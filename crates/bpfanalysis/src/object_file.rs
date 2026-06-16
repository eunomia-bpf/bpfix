use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget, SectionIndex,
    SectionKind, SymbolKind,
};

use crate::analysis::{lift_with_pass_context, ProgramCFG};
use crate::insn::{BpfInsn, BPF_PSEUDO_CALL};
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
    let code_layout = ObjectCodeLayout::from_file(&file)
        .with_context(|| format!("failed to inspect BPF object {}", path.display()))?;
    let mut summaries = Vec::new();
    let (verifier_states, verifier_state_parse_error, verifier_function_starts) =
        parse_verifier_states(verifier_log);

    for section in file.sections() {
        if !is_program_entry_section(&section) {
            continue;
        }
        let name = section.name().unwrap_or("<unnamed>").to_string();
        let insns = code_layout
            .loaded_program_insns(section.index())
            .with_context(|| format!("failed to reconstruct loaded program for section {name}"))?;
        if insns.is_empty() {
            continue;
        }

        let instruction_count = insns.len();
        let (cfg, verifier_state_attach_error) = match lift_program_cfg(
            &insns,
            verifier_states.as_deref(),
            &verifier_function_starts,
            verifier_state_parse_error.as_deref(),
        ) {
            Ok(result) => result,
            Err(err) => {
                let error = format!("failed to lift section {name} into ProgramCFG: {err:#}");
                summaries.push(failed_section_summary(name, instruction_count, error));
                continue;
            }
        };
        let site_count = cfg.all_sites().count();
        let verifier_state_site_count =
            verifier_state_site_count(&cfg, verifier_state_attach_error.is_none());
        summaries.push(ObjectProgramSummary {
            section_name: name,
            instruction_count,
            block_count: cfg.blocks().count(),
            site_count,
            verifier_state_site_count,
            verifier_state_attach_error,
        });
    }

    mark_ambiguous_state_attachments(&mut summaries);
    Ok(summaries)
}

fn failed_section_summary(
    section_name: String,
    instruction_count: usize,
    error: String,
) -> ObjectProgramSummary {
    ObjectProgramSummary {
        section_name,
        instruction_count,
        block_count: 0,
        site_count: 0,
        verifier_state_site_count: 0,
        verifier_state_attach_error: Some(error),
    }
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
) -> (Option<Vec<VerifierInsn>>, Option<String>, Vec<usize>) {
    let Some(log) = verifier_log else {
        return (None, None, Vec::new());
    };
    let function_starts = verifier_function_starts(log);
    match verifier_states_from_log(log) {
        Ok(states) => (Some(states), None, function_starts),
        Err(err) => (None, Some(err.to_string()), function_starts),
    }
}

fn verifier_function_starts(log: &str) -> Vec<usize> {
    log.lines()
        .filter_map(|line| line.trim().strip_prefix("func#"))
        .filter_map(|line| line.split_once('@').map(|(_, pc)| pc.trim()))
        .filter_map(|pc| pc.parse().ok())
        .collect()
}

fn lift_program_cfg(
    insns: &[BpfInsn],
    verifier_states: Option<&[VerifierInsn]>,
    verifier_function_starts: &[usize],
    verifier_state_parse_error: Option<&str>,
) -> Result<(ProgramCFG, Option<String>)> {
    let Some(states) = verifier_states.filter(|states| !states.is_empty()) else {
        return Ok((
            lift_without_verifier_states(insns)?,
            verifier_state_parse_error.map(ToOwned::to_owned),
        ));
    };
    let original_state_count = states.len();
    let states = states
        .iter()
        .filter(|state| state.pc < insns.len())
        .cloned()
        .collect::<Vec<_>>();
    if states.len() < original_state_count && !verifier_function_starts.contains(&insns.len()) {
        return Ok((lift_without_verifier_states(insns)?, None));
    }
    if states.is_empty() {
        return Ok((lift_without_verifier_states(insns)?, None));
    }

    let mut ctx = PassContext::default();
    ctx.set_verifier_states(states);
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

#[derive(Clone, Debug)]
struct CodeSection {
    name: String,
    insns: Vec<BpfInsn>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ProgramKey {
    section_index: SectionIndex,
    sec_insn_off: usize,
}

#[derive(Clone, Debug)]
struct ProgramSlice {
    key: ProgramKey,
    name: String,
    sec_insn_cnt: usize,
}

#[derive(Clone, Debug)]
struct CallRelocation {
    target_section: SectionIndex,
    sym_off_insns: i64,
}

#[derive(Clone, Debug)]
struct ObjectCodeLayout {
    sections: HashMap<SectionIndex, CodeSection>,
    subprograms: Vec<ProgramSlice>,
    call_relocations: HashMap<(SectionIndex, usize), CallRelocation>,
}

impl ObjectCodeLayout {
    fn from_file(file: &object::File<'_>) -> Result<Self> {
        let mut sections = HashMap::new();
        for section in file.sections() {
            if !is_code_container_section(&section) {
                continue;
            }
            let name = section.name().unwrap_or("<unnamed>").to_string();
            let data = section
                .data()
                .with_context(|| format!("failed to read section {name}"))?;
            let insns = decode_bpf_insns(data)
                .with_context(|| format!("failed to decode section {name} as BPF instructions"))?;
            if insns.is_empty() {
                continue;
            }
            sections.insert(section.index(), CodeSection { name, insns });
        }

        let subprograms = collect_subprograms(file, &sections)?;
        let call_relocations = collect_call_relocations(file, &sections)?;
        Ok(Self {
            sections,
            subprograms,
            call_relocations,
        })
    }

    fn loaded_program_insns(&self, section_index: SectionIndex) -> Result<Vec<BpfInsn>> {
        let section = self
            .sections
            .get(&section_index)
            .ok_or_else(|| anyhow::anyhow!("section {section_index} is not executable BPF code"))?;
        let entry = ProgramSlice {
            key: ProgramKey {
                section_index,
                sec_insn_off: 0,
            },
            name: section.name.clone(),
            sec_insn_cnt: section.insns.len(),
        };
        let mut builder = LoadedProgramBuilder::new(self);
        Ok(builder
            .build(&entry)
            .unwrap_or_else(|_| section.insns.clone()))
    }

    fn program_insns(&self, program: &ProgramSlice) -> Result<&[BpfInsn]> {
        let section = self
            .sections
            .get(&program.key.section_index)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "program {} references missing section {}",
                    program.name,
                    program.key.section_index
                )
            })?;
        let start = program.key.sec_insn_off;
        let end = start.checked_add(program.sec_insn_cnt).ok_or_else(|| {
            anyhow::anyhow!("program {} instruction range overflows", program.name)
        })?;
        section.insns.get(start..end).ok_or_else(|| {
            anyhow::anyhow!(
                "program {} instruction range {start}..{end} is outside section {} length {}",
                program.name,
                section.name,
                section.insns.len()
            )
        })
    }

    fn call_relocation(
        &self,
        program: &ProgramSlice,
        local_insn_idx: usize,
    ) -> Option<&CallRelocation> {
        let section_pc = program.key.sec_insn_off.checked_add(local_insn_idx)?;
        self.call_relocations
            .get(&(program.key.section_index, section_pc))
    }

    fn find_subprogram(
        &self,
        section_index: SectionIndex,
        section_pc: usize,
    ) -> Option<&ProgramSlice> {
        self.subprograms
            .iter()
            .filter(|program| program.key.section_index == section_index)
            .filter(|program| {
                let start = program.key.sec_insn_off;
                let end = start.saturating_add(program.sec_insn_cnt);
                start <= section_pc && section_pc < end
            })
            .max_by_key(|program| program.key.sec_insn_off)
    }
}

struct LoadedProgramBuilder<'a> {
    layout: &'a ObjectCodeLayout,
    loaded: Vec<BpfInsn>,
    loaded_offsets: HashMap<ProgramKey, usize>,
    relocating: HashSet<ProgramKey>,
    relocated: HashSet<ProgramKey>,
}

impl<'a> LoadedProgramBuilder<'a> {
    fn new(layout: &'a ObjectCodeLayout) -> Self {
        Self {
            layout,
            loaded: Vec::new(),
            loaded_offsets: HashMap::new(),
            relocating: HashSet::new(),
            relocated: HashSet::new(),
        }
    }

    fn build(&mut self, entry: &ProgramSlice) -> Result<Vec<BpfInsn>> {
        let entry_loaded_off = self.append_program(entry)?;
        self.relocate_program(entry, entry_loaded_off)?;
        Ok(std::mem::take(&mut self.loaded))
    }

    fn append_program(&mut self, program: &ProgramSlice) -> Result<usize> {
        if let Some(offset) = self.loaded_offsets.get(&program.key).copied() {
            return Ok(offset);
        }
        let offset = self.loaded.len();
        self.loaded
            .extend_from_slice(self.layout.program_insns(program)?);
        self.loaded_offsets.insert(program.key, offset);
        Ok(offset)
    }

    fn relocate_program(&mut self, program: &ProgramSlice, loaded_off: usize) -> Result<()> {
        if self.relocated.contains(&program.key) {
            return Ok(());
        }
        if !self.relocating.insert(program.key) {
            return Ok(());
        }
        let original_insns = self.layout.program_insns(program)?;
        for local_insn_idx in 0..program.sec_insn_cnt {
            let loaded_pc = loaded_off + local_insn_idx;
            if self.loaded.get(loaded_pc).is_none() {
                anyhow::bail!(
                    "program {} loaded pc {loaded_pc} is outside loaded instruction array",
                    program.name
                );
            };
            let Some(insn) = original_insns.get(local_insn_idx).copied() else {
                anyhow::bail!(
                    "program {} local instruction {local_insn_idx} is outside original body",
                    program.name
                );
            };
            if !is_pseudo_call(&insn) {
                continue;
            }

            let (target_section, target_section_pc) =
                self.subprogram_target(program, local_insn_idx, &insn)?;
            let subprogram = self
                .layout
                .find_subprogram(target_section, target_section_pc)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "pseudo-call in {} at section pc {} targets section {} pc {}, \
                         but no matching .text subprogram symbol was found",
                        program.name,
                        program.key.sec_insn_off + local_insn_idx,
                        target_section,
                        target_section_pc
                    )
                })?;
            let subprogram_loaded_off = self.append_program(subprogram)?;
            self.relocate_program(subprogram, subprogram_loaded_off)?;

            let delta = subprogram_loaded_off as i64 - loaded_pc as i64 - 1;
            self.loaded[loaded_pc]
                .set_pc_relative_imm_delta(delta)
                .with_context(|| {
                    format!(
                        "failed to relocate pseudo-call in {} at loaded pc {loaded_pc}",
                        program.name
                    )
                })?;
        }
        self.relocating.remove(&program.key);
        self.relocated.insert(program.key);
        Ok(())
    }

    fn subprogram_target(
        &self,
        program: &ProgramSlice,
        local_insn_idx: usize,
        insn: &BpfInsn,
    ) -> Result<(SectionIndex, usize)> {
        if let Some(relo) = self.layout.call_relocation(program, local_insn_idx) {
            // libbpf records R_BPF_64_32 subprogram calls as sym_off + insn->imm + 1.
            // Global function calls normally carry imm=-1; static calls through a
            // section symbol carry the callee start in imm.
            let target = relo.sym_off_insns + i64::from(insn.imm) + 1;
            let target = usize::try_from(target).with_context(|| {
                format!(
                    "pseudo-call relocation in {} at section pc {} underflows",
                    program.name,
                    program.key.sec_insn_off + local_insn_idx
                )
            })?;
            return Ok((relo.target_section, target));
        }

        let target =
            program.key.sec_insn_off as i64 + local_insn_idx as i64 + i64::from(insn.imm) + 1;
        let target = usize::try_from(target).with_context(|| {
            format!(
                "section-local pseudo-call in {} at section pc {} underflows",
                program.name,
                program.key.sec_insn_off + local_insn_idx
            )
        })?;
        Ok((program.key.section_index, target))
    }
}

fn collect_subprograms(
    file: &object::File<'_>,
    sections: &HashMap<SectionIndex, CodeSection>,
) -> Result<Vec<ProgramSlice>> {
    let mut candidates = Vec::new();
    for symbol in file.symbols() {
        if symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
            continue;
        }
        let Some(section_index) = symbol.section_index() else {
            continue;
        };
        let Some(section) = sections.get(&section_index) else {
            continue;
        };
        if section.name != ".text" {
            continue;
        }
        let start = symbol_offset_insns(file, symbol.index())?;
        let count = checked_insn_count(
            symbol.size(),
            "symbol size",
            symbol.name().unwrap_or("<unnamed>"),
        )?;
        let end = start.checked_add(count).ok_or_else(|| {
            anyhow::anyhow!(
                "subprogram {} instruction range overflows",
                symbol.name().unwrap_or("<unnamed>")
            )
        })?;
        if end > section.insns.len() {
            continue;
        }
        candidates.push(ProgramSlice {
            key: ProgramKey {
                section_index,
                sec_insn_off: start,
            },
            name: symbol.name().unwrap_or("<unnamed>").to_string(),
            sec_insn_cnt: count,
        });
    }
    candidates.sort_by_key(|program| (program.key.section_index.0, program.key.sec_insn_off));
    Ok(candidates)
}

fn collect_call_relocations(
    file: &object::File<'_>,
    sections: &HashMap<SectionIndex, CodeSection>,
) -> Result<HashMap<(SectionIndex, usize), CallRelocation>> {
    let mut call_relocations = HashMap::new();
    for object_section in file.sections() {
        let section_index = object_section.index();
        let Some(section) = sections.get(&section_index) else {
            continue;
        };
        for (offset, relocation) in object_section.relocations() {
            if relocation.kind() != RelocationKind::Absolute || relocation.size() != 32 {
                continue;
            }
            if !offset.is_multiple_of(8) {
                continue;
            }
            let insn_idx = (offset / 8) as usize;
            let Some(insn) = section.insns.get(insn_idx) else {
                continue;
            };
            if !is_pseudo_call(insn) {
                continue;
            }
            let Some((target_section, sym_off_insns)) =
                relocation_symbol_offset_insns(file, relocation.target(), sections)?
            else {
                continue;
            };
            call_relocations.insert(
                (section_index, insn_idx),
                CallRelocation {
                    target_section,
                    sym_off_insns,
                },
            );
        }
    }
    Ok(call_relocations)
}

fn relocation_symbol_offset_insns(
    file: &object::File<'_>,
    target: RelocationTarget,
    sections: &HashMap<SectionIndex, CodeSection>,
) -> Result<Option<(SectionIndex, i64)>> {
    match target {
        RelocationTarget::Symbol(symbol_index) => {
            let symbol = file.symbol_by_index(symbol_index)?;
            let Some(section_index) = symbol.section_index() else {
                return Ok(None);
            };
            if !sections.contains_key(&section_index) {
                return Ok(None);
            }
            let offset = symbol_offset_insns(file, symbol_index)?;
            Ok(Some((section_index, offset as i64)))
        }
        RelocationTarget::Section(section_index) => {
            if sections.contains_key(&section_index) {
                Ok(Some((section_index, 0)))
            } else {
                Ok(None)
            }
        }
        RelocationTarget::Absolute => Ok(None),
        _ => Ok(None),
    }
}

fn symbol_offset_insns(
    file: &object::File<'_>,
    symbol_index: object::SymbolIndex,
) -> Result<usize> {
    let symbol = file.symbol_by_index(symbol_index)?;
    let section_index = symbol
        .section_index()
        .ok_or_else(|| anyhow::anyhow!("symbol {symbol_index} has no section"))?;
    let section = file.section_by_index(section_index)?;
    let offset = symbol
        .address()
        .checked_sub(section.address())
        .ok_or_else(|| anyhow::anyhow!("symbol {symbol_index} address is before its section"))?;
    checked_insn_offset(
        offset,
        "symbol offset",
        symbol.name().unwrap_or("<unnamed>"),
    )
}

fn checked_insn_offset(value: u64, label: &str, name: &str) -> Result<usize> {
    if !value.is_multiple_of(8) {
        anyhow::bail!("{label} for {name} is not BPF-instruction aligned: {value}");
    }
    usize::try_from(value / 8).with_context(|| format!("{label} for {name} does not fit in usize"))
}

fn checked_insn_count(value: u64, label: &str, name: &str) -> Result<usize> {
    if !value.is_multiple_of(8) {
        anyhow::bail!("{label} for {name} is not a whole number of BPF instructions: {value}");
    }
    usize::try_from(value / 8).with_context(|| format!("{label} for {name} does not fit in usize"))
}

fn is_pseudo_call(insn: &BpfInsn) -> bool {
    insn.is_call() && insn.src_reg() == BPF_PSEUDO_CALL
}

fn is_code_container_section(section: &object::Section<'_, '_>) -> bool {
    section.name().is_ok_and(|name| name == ".text") || is_program_entry_section(section)
}

fn is_program_entry_section(section: &object::Section<'_, '_>) -> bool {
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
    section.size() > 0 && section.size().is_multiple_of(8)
}

fn decode_bpf_insns(data: &[u8]) -> Result<Vec<BpfInsn>> {
    if !data.len().is_multiple_of(8) {
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
