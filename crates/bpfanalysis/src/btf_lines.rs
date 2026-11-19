// SPDX-License-Identifier: MIT
//! BTF line information from a compiled BPF object.
//!
//! Kernels before 6.9 print the source text of each verifier log line but omit
//! the ` @ file:line` suffix (added by kernel commit 7cc13adbd057), so the
//! verifier log alone cannot place a failure in the source. The object carries
//! the same mapping in `.BTF.ext`: for every instruction offset, the file name
//! and line. This module reads that table so a caller can match the source text
//! the log does print against the source the object was built from.

use std::collections::BTreeMap;
#[cfg(feature = "object-analysis")]
use std::path::Path;

#[cfg(feature = "object-analysis")]
use anyhow::{Context, Result};
#[cfg(feature = "object-analysis")]
use object::{Object, ObjectSection};

const BTF_MAGIC: u16 = 0xeb9f;
const BTF_MAGIC_SWAPPED: u16 = 0x9feb;
const BTF_LINE_REC_BASE_SIZE: u32 = 16;

/// One `.BTF.ext` line record: the instruction offset and the source line it
/// came from, with the source text BTF stores for that line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtfLineRecord {
    pub insn_off: u32,
    pub file: String,
    pub line: u32,
    pub text: String,
}

/// Read the `.BTF.ext` line table of a BPF object.
///
/// Returns an empty table when the object carries no BTF at all, which is
/// normal for objects built without `-g`.
#[cfg(feature = "object-analysis")]
pub fn load_btf_line_records(path: &Path) -> Result<Vec<BtfLineRecord>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read BPF object {}", path.display()))?;
    let file = object::File::parse(bytes.as_slice())
        .with_context(|| format!("failed to parse ELF object {}", path.display()))?;
    let Some(section) = section_named(&file, ".BTF.ext") else {
        return Ok(Vec::new());
    };
    let ext = section
        .data()
        .with_context(|| format!("failed to read .BTF.ext of {}", path.display()))?;
    let Some(btf) = section_named(&file, ".BTF") else {
        return Ok(Vec::new());
    };
    let strings_section = btf
        .data()
        .with_context(|| format!("failed to read .BTF of {}", path.display()))?;
    let strings = btf_string_section(strings_section)
        .with_context(|| format!("failed to parse .BTF strings of {}", path.display()))?;
    parse_btf_ext_lines(ext, strings)
        .with_context(|| format!("failed to parse .BTF.ext of {}", path.display()))
}

#[cfg(feature = "object-analysis")]
fn section_named<'a>(file: &'a object::File<'a>, name: &str) -> Option<object::Section<'a, 'a>> {
    file.sections()
        .find(|section| section.name().ok() == Some(name))
}

#[cfg(feature = "object-analysis")]
fn btf_string_section(btf: &[u8]) -> Result<&str> {
    let header = parse_header(btf)?;
    let start = header.hdr_len as usize + header.str_off as usize;
    let end = start + header.str_len as usize;
    let raw = btf
        .get(start..end)
        .context(".BTF string section runs past the section end")?;
    std::str::from_utf8(raw).context(".BTF string section is not UTF-8")
}

#[cfg(feature = "object-analysis")]
fn parse_btf_ext_lines(ext: &[u8], strings: &str) -> Result<Vec<BtfLineRecord>> {
    let header = parse_header(ext)?;
    if header.line_len == 0 {
        return Ok(Vec::new());
    }
    let start = header.hdr_len as usize + header.line_off as usize;
    let end = start + header.line_len as usize;
    let lines = ext
        .get(start..end)
        .context(".BTF.ext line section runs past the section end")?;
    let Some((rec_size, body)) = lines.split_first_chunk::<4>() else {
        return Ok(Vec::new());
    };
    let rec_size = u32::from_le_bytes(*rec_size);
    if rec_size < BTF_LINE_REC_BASE_SIZE {
        anyhow::bail!(
            ".BTF.ext line record size {rec_size} is smaller than the 16-byte base record"
        );
    }
    let rec_size = rec_size as usize;
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset + 8 <= body.len() {
        let section_name_off = u32::from_le_bytes(body[offset..offset + 4].try_into()?);
        let count = u32::from_le_bytes(body[offset + 4..offset + 8].try_into()?);
        offset += 8;
        let _ = section_name_off;
        for _ in 0..count {
            let Some(record) = body.get(offset..offset + rec_size) else {
                break;
            };
            offset += rec_size;
            let insn_off = u32::from_le_bytes(record[0..4].try_into()?);
            let file_off = u32::from_le_bytes(record[4..8].try_into()?);
            let line_off = u32::from_le_bytes(record[8..12].try_into()?);
            let line_col = u32::from_le_bytes(record[12..16].try_into()?);
            records.push(BtfLineRecord {
                insn_off,
                file: btf_string(strings, file_off).to_string(),
                line: line_col >> 10,
                text: btf_string(strings, line_off).to_string(),
            });
        }
    }
    Ok(records)
}

#[cfg(feature = "object-analysis")]
struct BtfHeader {
    hdr_len: u32,
    line_off: u32,
    line_len: u32,
    str_off: u32,
    str_len: u32,
}

#[cfg(feature = "object-analysis")]
fn parse_header(blob: &[u8]) -> Result<BtfHeader> {
    let Some(prefix) = blob.get(0..24) else {
        anyhow::bail!("BTF section is shorter than its 24-byte header");
    };
    let magic = u16::from_le_bytes(prefix[0..2].try_into()?);
    if magic != BTF_MAGIC && magic != BTF_MAGIC_SWAPPED {
        anyhow::bail!("BTF section has unexpected magic {magic:#06x}");
    }
    // Byte order follows the magic: a swapped magic means the fields are
    // big-endian relative to the file we read.
    let read = if magic == BTF_MAGIC {
        u32::from_le_bytes
    } else {
        u32::from_be_bytes
    };
    // `.BTF` and `.BTF.ext` agree on the two fields read here: the string
    // section offset in `.BTF` and the line section offset in `.BTF.ext` both
    // follow `type_len`/`func_info_len` at byte 16, with their length at 20.
    Ok(BtfHeader {
        hdr_len: read(prefix[4..8].try_into()?),
        line_off: read(prefix[16..20].try_into()?),
        line_len: read(prefix[20..24].try_into()?),
        str_off: read(prefix[16..20].try_into()?),
        str_len: read(prefix[20..24].try_into()?),
    })
}

fn btf_string(strings: &str, offset: u32) -> &str {
    let Some(tail) = strings.get(offset as usize..) else {
        return "";
    };
    tail.split('\0').next().unwrap_or("")
}

/// Index line records by source text, keeping every instruction offset a text
/// appears at. A text that occurs once is a safe fallback for a verifier log
/// line that carries no location; a text that occurs more than once is not.
pub fn index_lines_by_text(records: &[BtfLineRecord]) -> BTreeMap<&str, Vec<&BtfLineRecord>> {
    let mut index = BTreeMap::new();
    for record in records {
        let text = record.text.trim();
        if text.is_empty() {
            continue;
        }
        index.entry(text).or_insert_with(Vec::new).push(record);
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "object-analysis")]
    #[test]
    fn header_requires_btf_magic() {
        let mut blob = vec![0u8; 32];
        blob[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
        assert!(parse_header(&blob).is_err());
    }

    #[cfg(feature = "object-analysis")]
    #[test]
    fn string_lookup_stops_at_the_terminator() {
        let strings = "first\0second\0";
        assert_eq!(btf_string(strings, 0), "first");
        assert_eq!(btf_string(strings, 6), "second");
        assert_eq!(btf_string(strings, 1000), "");
    }

    #[cfg(feature = "object-analysis")]
    #[test]
    fn reads_line_records_from_a_compiled_object() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../bpfix-empirical/cases/stackoverflow-78591601/prog.o");
        if !path.is_file() {
            return;
        }
        let records = load_btf_line_records(&path).unwrap();

        assert!(
            !records.is_empty(),
            "the corpus object carries .BTF.ext lines"
        );
        assert!(
            records
                .iter()
                .any(|record| record.text.contains("data_end")),
            "source text comes from BTF, not the verifier log"
        );
        assert!(records.iter().all(|record| record.line >= 1));
    }

    #[test]
    fn text_index_keeps_repeated_text_ambiguous() {
        let records = vec![
            BtfLineRecord {
                insn_off: 0,
                file: "prog.c".to_string(),
                line: 4,
                text: "  return 0;".to_string(),
            },
            BtfLineRecord {
                insn_off: 8,
                file: "prog.c".to_string(),
                line: 9,
                text: "  return 0;".to_string(),
            },
        ];
        let index = index_lines_by_text(&records);
        assert_eq!(index.len(), 1);
        assert_eq!(index["return 0;"].len(), 2);
    }
}
