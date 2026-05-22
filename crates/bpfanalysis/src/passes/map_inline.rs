// SPDX-License-Identifier: MIT
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapInlineHintMode {
    Soft,
    Hard,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MapInlineHintAnchorSpec {
    Pc(usize),
    MapName(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapInlineHintSpec {
    pub anchor: MapInlineHintAnchorSpec,
    pub mode: MapInlineHintMode,
    pub key: Vec<u8>,
}

/// Pre-loaded map metadata used by analysis and pass context plumbing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapInfo {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_id: u32,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedMapValues {
    pub value_size: usize,
    pub kind: CompressedMapValuesKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompressedMapValuesKind {
    Uniform(Vec<u8>),
    Sparse {
        default: Vec<u8>,
        entries: HashMap<Vec<u8>, Vec<u8>>,
    },
    Enumerated {
        entries: HashMap<Vec<u8>, Vec<u8>>,
    },
}

impl CompressedMapValues {
    pub fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        match &self.kind {
            CompressedMapValuesKind::Uniform(value) => Some(value.clone()),
            CompressedMapValuesKind::Sparse { default, entries } => {
                entries.get(key).cloned().or_else(|| Some(default.clone()))
            }
            CompressedMapValuesKind::Enumerated { entries } => entries.get(key).cloned(),
        }
    }
}
