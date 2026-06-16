// SPDX-License-Identifier: MIT
//! Parser and low-level query helpers for BPF verifier logs captured with
//! `log_level=2`.
//!
//! The stable crate-root surface exposes parsed verifier state records. This
//! module also contains raw helpers used by BPFix while the query layer is
//! being consolidated into a higher-level trace API.
//! Instruction text query helpers are public because BPFix consumes this crate
//! as a separate package; they are narrow verifier-log scanners, not a complete
//! BPF assembly parser.
//!
//! The verifier emits state snapshots in a few common forms:
//! - `from <prev> to <pc>: R0=... R1=...`
//! - `<pc>: R0=... R1=...`
//! - `<pc>: (..insn..) ... ; R0=... R1=...`
//!
//! This module extracts per-PC register state summaries that feed later
//! optimization analyses (constant propagation, range checks, liveness, etc.).
use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifierInsnKind {
    EdgeFullState,
    PcFullState,
    BranchDeltaState,
    InsnDeltaState,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackKind {
    Sync,
    Async,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifierValueWidth {
    Unknown,
    Bits32,
    Bits64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tnum {
    pub value: u64,
    pub mask: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScalarRange {
    pub smin: Option<i64>,
    pub smax: Option<i64>,
    pub umin: Option<u64>,
    pub umax: Option<u64>,
    pub smin32: Option<i32>,
    pub smax32: Option<i32>,
    pub umin32: Option<u32>,
    pub umax32: Option<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierInsn {
    pub pc: usize,
    pub log_line: usize,
    pub frame: usize,
    pub from_pc: Option<usize>,
    pub kind: VerifierInsnKind,
    pub speculative: bool,
    pub regs: HashMap<u8, RegState>,
    pub stack: HashMap<i16, StackState>,
    pub refs: Option<u32>,
    pub ref_ids: Vec<u32>,
    pub callback_kind: Option<CallbackKind>,
    pub callback: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegState {
    pub reg_type: String,
    pub value_width: VerifierValueWidth,
    pub precise: bool,
    pub exact_value: Option<u64>,
    pub tnum: Option<Tnum>,
    pub range: ScalarRange,
    pub packet_range: Option<u32>,
    pub map_value_size: Option<u32>,
    pub mem_size: Option<u32>,
    pub offset: Option<i32>,
    pub source_frame: Option<usize>,
    pub id: Option<u32>,
    pub ref_id: Option<u32>,
}
impl RegState {
    pub fn new(reg_type: impl Into<String>, value_width: VerifierValueWidth) -> Self {
        Self {
            reg_type: reg_type.into(),
            value_width,
            precise: false,
            exact_value: None,
            tnum: None,
            range: ScalarRange::default(),
            packet_range: None,
            map_value_size: None,
            mem_size: None,
            offset: None,
            source_frame: None,
            id: None,
            ref_id: None,
        }
    }
    pub fn exact_u64(&self) -> Option<u64> {
        if self.reg_type != "scalar" {
            return None;
        }
        match self.value_width {
            VerifierValueWidth::Bits32 => None,
            VerifierValueWidth::Bits64 | VerifierValueWidth::Unknown => self.exact_value,
        }
    }
    pub fn exact_u32(&self) -> Option<u32> {
        if self.reg_type != "scalar" {
            return None;
        }
        self.exact_value.map(|value| value as u32)
    }

    pub fn exact_scalar_value(&self) -> Option<u64> {
        self.exact_u64().or_else(|| self.exact_u32().map(u64::from))
    }

    pub fn is_exact_zero_scalar(&self) -> bool {
        self.exact_scalar_value() == Some(0)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackState {
    pub slot_types: Option<String>,
    pub value: Option<RegState>,
}

/// Parses the verifier-log PC prefix from `<pc>:` lines.
///
/// This intentionally accepts both opcode rows and state-only rows such as
/// `17: R1=ctx()`. Use [`parse_instruction_line`] when the caller needs an
/// actual opcode tail.
pub fn parse_instruction_pc(line: &str) -> Option<usize> {
    parse_instruction_prefix(line).map(|(pc, _)| pc)
}

/// Parses a verifier opcode row and returns its PC plus opcode tail.
pub fn parse_instruction_line(line: &str) -> Option<(usize, &str)> {
    let (pc, tail) = parse_instruction_prefix(line)?;
    Some((pc, instruction_opcode_tail(tail.trim_start())?))
}

/// Extracts the token after the first `call` word in an instruction tail.
///
/// This is a loose helper for already-filtered verifier rows. Use
/// [`direct_call_target_from_instruction_tail`] when the caller needs to prove
/// that the tail is exactly a direct BPF call instruction.
pub fn call_target_from_instruction_tail(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    let call = loop {
        let token = tokens.next()?;
        if token == "call" {
            break tokens.next()?;
        }
    };
    call.split_once('#')
        .map(|(target, _)| target)
        .or(Some(call))
}

/// Extracts the target from a strict `(85) call <target>` instruction tail.
pub fn direct_call_target_from_instruction_tail(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "(85)" || tokens.next()? != "call" {
        return None;
    }
    let call = tokens.next()?;
    call.split_once('#')
        .map(|(target, _)| target)
        .or(Some(call))
}

/// Scans textual operands for `rN` register mentions.
///
/// This is intentionally a lightweight verifier-log scanner, not a complete
/// BPF assembly lexer. It does not include `wN` write aliases.
pub fn loose_register_operands(text: &str) -> Vec<u8> {
    let mut regs = Vec::new();
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    while idx + 1 < bytes.len() {
        if bytes[idx] != b'r' || !bytes[idx + 1].is_ascii_digit() {
            idx += 1;
            continue;
        }
        let start = idx + 1;
        let mut end = start + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if let Ok(reg) = text[start..end].parse::<u8>() {
            regs.push(reg);
        }
        idx = end;
    }
    regs
}

pub fn register_token(token: &str) -> Option<u8> {
    parse_register_token(token, false)
}

pub fn register_write_token(token: &str) -> Option<u8> {
    parse_register_token(token, true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierLogInstruction<'a> {
    pub pc: usize,
    pub line: usize,
    pub tail: &'a str,
}

#[derive(Clone, Debug)]
pub struct PathVerifierSnapshot {
    pub frame: usize,
    pub regs: HashMap<u8, RegState>,
    pub stack: HashMap<i16, StackState>,
}

pub fn memory_access_width(line_after_pc: &str) -> Option<u32> {
    let marker = "*(u";
    let start = line_after_pc.find(marker)? + marker.len();
    let bytes = line_after_pc.as_bytes();
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if line_after_pc.get(end..end + 3)? != " *)" {
        return None;
    }
    line_after_pc[start..end]
        .parse::<u32>()
        .ok()
        .and_then(|bits| bits.checked_div(8))
}

pub fn memory_access_is_load(line_after_pc: &str) -> bool {
    line_after_pc.contains("= *(")
}

pub fn memory_access_is_store(line_after_pc: &str) -> bool {
    !memory_access_is_load(line_after_pc)
        && line_after_pc.contains("*)(")
        && line_after_pc.contains(" = ")
}

pub fn instruction_opcode_body(line_after_pc: &str) -> &str {
    line_after_pc
        .split_once(';')
        .map_or(line_after_pc, |(body, _)| body)
        .trim()
}

pub fn instruction_destination_register(instruction_tail: &str) -> Option<u8> {
    let (_, rest) = instruction_tail.split_once(')')?;
    let lhs = rest.trim_start().split_once(" = ")?.0.trim();
    register_write_token(lhs)
}

pub fn instruction_assigns_register(instruction_tail: &str, reg: u8) -> bool {
    if reg == 0 && call_target_from_instruction_tail(instruction_tail).is_some() {
        return true;
    }
    let Some((_, rest)) = instruction_tail.split_once(')') else {
        return false;
    };
    let body = rest.split_once(';').map_or(rest, |(body, _)| body).trim();
    body.starts_with(&format!("r{reg} ")) || body.starts_with(&format!("w{reg} "))
}

pub fn instruction_writes_register(instruction_tail: &str, reg: u8) -> bool {
    let mut tokens = instruction_tail.split_whitespace();
    let Some(first) = tokens.next() else {
        return false;
    };
    let Some(destination) = (if first.starts_with('(') {
        tokens.next()
    } else {
        Some(first)
    }) else {
        return false;
    };
    if destination == "call" {
        return reg <= 5;
    }
    if register_write_token(destination) != Some(reg) {
        return false;
    }
    tokens
        .next()
        .is_some_and(|operator| operator.ends_with('='))
}

pub fn instruction_register_copy_source(instruction_tail: &str, destination: u8) -> Option<u8> {
    if instruction_destination_register(instruction_tail) != Some(destination) {
        return None;
    }
    let rhs = instruction_assignment_rhs(instruction_tail)?;
    register_token(rhs.trim())
}

pub fn instruction_single_register_rhs_source(
    instruction_tail: &str,
    destination: u8,
) -> Option<u8> {
    if instruction_destination_register(instruction_tail) != Some(destination) {
        return None;
    }
    let rhs = instruction_assignment_rhs(instruction_tail)?;
    if !rhs.starts_with('r') && !rhs.starts_with('w') {
        return None;
    }
    let regs = loose_register_operands(rhs);
    (regs.len() == 1).then_some(regs[0])
}

fn instruction_assignment_rhs(instruction_tail: &str) -> Option<&str> {
    let (_, rest) = instruction_tail.split_once(')')?;
    let (_, rhs) = rest
        .split_once(';')
        .map_or(rest, |(body, _)| body)
        .trim()
        .split_once(" = ")?;
    Some(rhs)
}

pub fn instruction_uses_register(instruction_tail: &str, reg: u8) -> bool {
    let needle = format!("r{reg}");
    instruction_tail
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token == needle)
}

pub fn instruction_reads_register(opcode_tail: &str, reg: u8) -> bool {
    if let Some(operand) = memory_access_operand(opcode_tail) {
        return loose_register_operands(operand).contains(&reg);
    }
    if opcode_tail.split_once(" = ").is_some() {
        return false;
    }
    loose_register_operands(opcode_tail).contains(&reg)
}

pub fn conditional_branch_registers(instruction_tail: &str) -> Vec<u8> {
    let Some(condition) = instruction_tail
        .split_once(" if ")
        .map(|(_, condition)| condition)
        .or_else(|| instruction_tail.strip_prefix("if "))
    else {
        return Vec::new();
    };
    let condition = condition.split(" goto ").next().unwrap_or(condition);
    loose_register_operands(condition)
}

pub fn instruction_adds_register(instruction_tail: &str, destination: u8, source: u8) -> bool {
    let mut tokens = instruction_tail.split_whitespace();
    while let Some(token) = tokens.next() {
        if register_token(token) != Some(destination) {
            continue;
        }
        if tokens.next() != Some("+=") {
            continue;
        }
        if tokens.next().and_then(register_token) == Some(source) {
            return true;
        }
    }
    false
}

pub fn memory_access_is_atomic(line_after_pc: &str) -> bool {
    let body = instruction_opcode_body(line_after_pc);
    (body.contains("atomic") && body.contains("*)(")) || body.contains("lock *(")
}

pub fn atomic_memory_access_width(line_after_pc: &str) -> Option<u32> {
    let body = instruction_opcode_body(line_after_pc);
    if !memory_access_is_atomic(body) {
        return None;
    }
    let marker = "(u";
    let bytes = body.as_bytes();
    let mut search_start = 0usize;
    while let Some(relative) = body[search_start..].find(marker) {
        let start = search_start + relative + marker.len();
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > start && body.get(end..end + 4) == Some(" *)(") {
            return body[start..end]
                .parse::<u32>()
                .ok()
                .and_then(|bits| bits.checked_div(8));
        }
        search_start = search_start + relative + marker.len();
    }
    None
}

pub fn memory_access_offset(line_after_pc: &str) -> Option<i64> {
    let operand = memory_access_operand(line_after_pc)?;
    if let Some((_, offset)) = operand.rsplit_once('+') {
        return parse_signed_decimal(offset);
    }
    if let Some((_, offset)) = operand.rsplit_once('-') {
        return parse_signed_decimal(offset).map(|value| -value);
    }
    loose_register_operands(operand).first().map(|_| 0)
}

pub fn memory_access_base_register(line_after_pc: &str) -> Option<u8> {
    loose_register_operands(memory_access_operand(line_after_pc)?)
        .first()
        .copied()
}

pub fn memory_access_operand(line_after_pc: &str) -> Option<&str> {
    let (_, after_marker) = line_after_pc.split_once("*)(")?;
    Some(after_marker.split_once(')')?.0.trim())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackByteRange {
    start: i16,
    end: i16,
}

impl StackByteRange {
    pub fn new(start: i16, end: i16) -> Option<Self> {
        (start <= end).then_some(Self { start, end })
    }

    pub fn start(self) -> i16 {
        self.start
    }

    pub fn end(self) -> i16 {
        self.end
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub fn contains(self, offset: i16) -> bool {
        self.start <= offset && offset < self.end
    }

    pub fn contains_range(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    pub fn len(self) -> i16 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

pub fn stack_value_range(offset: i16, size: i16) -> Option<StackByteRange> {
    if size < 0 {
        return None;
    }
    StackByteRange::new(offset, offset.checked_add(size)?)
}

pub fn stack_access_range(message: &str) -> Option<StackByteRange> {
    let offset = parse_signed_i16_after(message, "off ")?;
    let size = parse_signed_i16_after(message, "size ")?;
    stack_value_range(offset, size)
}

pub fn scalar_range_summary(state: &RegState) -> String {
    if let Some(value) = state.exact_value {
        return format!("scalar exact {value}");
    }
    let parts = scalar_range_parts(state);
    if parts.is_empty() {
        "scalar with unknown bounds".to_string()
    } else {
        format!("scalar({})", parts.join(","))
    }
}

pub fn verifier_value_summary(state: &RegState) -> String {
    if state.reg_type == "scalar" {
        return scalar_range_summary(state);
    }

    let mut parts = Vec::new();
    if let Some(offset) = state.offset {
        parts.push(format!("off={offset}"));
    }
    if let Some(value_size) = state.map_value_size {
        parts.push(format!("value_size={value_size}"));
    }
    let range = scalar_range_parts(state);
    if !range.is_empty() {
        parts.push(format!("range({})", range.join(",")));
    }

    if parts.is_empty() {
        state.reg_type.clone()
    } else {
        format!("{}({})", state.reg_type, parts.join(","))
    }
}

fn scalar_range_parts(state: &RegState) -> Vec<String> {
    let mut parts = Vec::new();
    if let Some(smin) = state.range.smin {
        parts.push(format!("smin={smin}"));
    }
    if let Some(smax) = state.range.smax {
        parts.push(format!("smax={smax}"));
    }
    if let Some(umin) = state.range.umin {
        parts.push(format!("umin={umin}"));
    }
    if let Some(umax) = state.range.umax {
        parts.push(format!("umax={umax}"));
    }
    parts
}

pub fn scalar_range_min_i64(state: &RegState) -> Option<i64> {
    state
        .range
        .smin
        .or_else(|| state.range.umin.and_then(|value| i64::try_from(value).ok()))
        .or_else(|| state.range.smin32.map(i64::from))
        .or_else(|| state.range.umin32.map(i64::from))
}

pub fn scalar_range_max_i64(state: &RegState) -> Option<i64> {
    state
        .range
        .smax
        .or_else(|| state.range.umax.and_then(|value| i64::try_from(value).ok()))
        .or_else(|| state.range.smax32.map(i64::from))
        .or_else(|| state.range.umax32.map(i64::from))
}

pub fn scalar_range_has_any_bound(state: &RegState) -> bool {
    state.range.smin.is_some()
        || state.range.smax.is_some()
        || state.range.umin.is_some()
        || state.range.umax.is_some()
        || state.range.smin32.is_some()
        || state.range.smax32.is_some()
        || state.range.umin32.is_some()
        || state.range.umax32.is_some()
}

pub fn scalar_ranges_match(left: &RegState, right: &RegState) -> bool {
    left.range.smin == right.range.smin
        && left.range.smax == right.range.smax
        && left.range.umin == right.range.umin
        && left.range.umax == right.range.umax
        && left.range.smin32 == right.range.smin32
        && left.range.smax32 == right.range.smax32
        && left.range.umin32 == right.range.umin32
        && left.range.umax32 == right.range.umax32
}

pub fn scalar_range_may_include_zero(state: &RegState) -> bool {
    if let Some(value) = state.exact_value {
        return value == 0;
    }
    if state.range.smax.is_some_and(|value| value < 0) {
        return false;
    }
    if state.range.smin.is_some_and(|value| value > 0) {
        return false;
    }
    if state.range.umin.is_some_and(|value| value > 0) {
        return false;
    }
    true
}

pub fn scalar_range_may_be_negative(state: &RegState) -> bool {
    if let Some(value) = state.exact_value {
        return value > i64::MAX as u64;
    }
    if let Some(smin) = state.range.smin {
        return smin < 0;
    }
    state.range.umin.is_none()
}

pub fn scalar_range_upper_unbounded_or_too_large(state: &RegState) -> bool {
    let signed_too_large = state
        .range
        .smax
        .is_some_and(|value| value > i32::MAX as i64);
    let unsigned_too_large = state
        .range
        .umax
        .is_some_and(|value| value > i32::MAX as u64);
    let unbounded = state.range.smax.is_none() && state.range.umax.is_none();
    signed_too_large || unsigned_too_large || unbounded
}

pub fn scalar_range_is_unsafe(state: &RegState) -> bool {
    state.range.smin.is_none_or(|value| value < 0)
        || state.range.umin.is_none()
        || state.range.umax.is_none_or(|value| value > i32::MAX as u64)
}

pub fn scalar_state_upper_bound_at_most(state: &RegState, relation_capacity: u32) -> bool {
    if state.reg_type != "scalar" {
        return false;
    }
    let capacity = u64::from(relation_capacity);
    state.exact_value.is_some_and(|value| value <= capacity)
        || state.range.umax.is_some_and(|value| value <= capacity)
        || state
            .range
            .smax
            .is_some_and(|value| value >= 0 && value as u64 <= capacity)
        || state
            .range
            .umax32
            .is_some_and(|value| value <= relation_capacity)
        || state
            .range
            .smax32
            .is_some_and(|value| value >= 0 && value as u32 <= relation_capacity)
}

pub fn map_value_remaining_capacity(state: &RegState, value_size: u32) -> Option<u32> {
    let fixed_offset = state.offset.unwrap_or(0);
    let fixed_offset = u32::try_from(fixed_offset).ok()?;
    value_size.checked_sub(fixed_offset)
}

pub fn map_value_variable_max_offset(state: &RegState) -> Option<u64> {
    state
        .range
        .umax
        .or_else(|| state.range.smax.and_then(|value| u64::try_from(value).ok()))
}

pub fn map_value_access_range_may_exceed_value_size(state: &RegState, access_size: u32) -> bool {
    if state.reg_type != "map_value" {
        return false;
    }
    let Some(value_size) = state.map_value_size else {
        return false;
    };
    map_value_max_offset(state, Some(0))
        .and_then(|offset| offset.checked_add(u64::from(access_size)))
        .is_some_and(|end| end > u64::from(value_size))
}

pub fn map_value_range_may_exceed_value_size(state: &RegState) -> bool {
    if state.reg_type != "map_value" {
        return false;
    }
    let Some(value_size) = state.map_value_size else {
        return false;
    };
    map_value_max_offset(state, None).is_some_and(|offset| offset >= u64::from(value_size))
}

fn map_value_max_offset(state: &RegState, default_without_offset: Option<u64>) -> Option<u64> {
    let max_variable_offset = map_value_variable_max_offset(state);
    let fixed_offset = state.offset.and_then(|offset| u64::try_from(offset).ok());
    match (fixed_offset, max_variable_offset) {
        (Some(fixed), Some(variable)) => fixed.checked_add(variable),
        (Some(fixed), None) => Some(fixed),
        (None, Some(variable)) => Some(variable),
        (None, None) => default_without_offset,
    }
}

fn parse_signed_i16_after(message: &str, marker: &str) -> Option<i16> {
    let start = message.find(marker)? + marker.len();
    let rest = message[start..].trim_start();
    let bytes = rest.as_bytes();
    let mut end = 0usize;
    if matches!(bytes.first(), Some(b'-' | b'+')) {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || matches!(rest.as_bytes().get(..end), Some([b'-']) | Some([b'+'])) {
        return None;
    }
    rest[..end].parse::<i16>().ok()
}

pub fn latest_reg_state_before(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<&RegState> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .filter_map(|state| state.regs.get(&reg))
        .next()
}

pub fn latest_unsafe_scalar_state(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<(usize, &RegState)> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            ((reg_state.reg_type == "scalar" && scalar_range_is_unsafe(reg_state))
                || map_value_range_may_exceed_value_size(reg_state))
            .then_some((state.pc, reg_state))
        })
}

pub fn latest_nullable_state(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<(usize, String)> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .find_map(|state| {
            let reg_state = state.regs.get(&reg)?;
            reg_state
                .reg_type
                .contains("_or_null")
                .then(|| (state.pc, reg_state.reg_type.clone()))
        })
}

pub fn latest_reg_state_index_before(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<(usize, &VerifierInsn, &RegState)> {
    states
        .iter()
        .enumerate()
        .filter(|(_, state)| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .find_map(|(idx, state)| {
            state
                .regs
                .get(&reg)
                .map(|reg_state| (idx, state, reg_state))
        })
}

pub fn latest_reg_state_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<&'a RegState> {
    latest_reg_state_for_instruction(
        states,
        instruction,
        fragment_start_line,
        reg,
        false,
        |_, reg| reg,
    )
}

pub fn latest_reg_state_at_or_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<&'a RegState> {
    latest_reg_state_for_instruction(
        states,
        instruction,
        fragment_start_line,
        reg,
        true,
        |_, reg| reg,
    )
}

pub fn latest_reg_state_before_instruction_with_log_line<'a>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<(&'a RegState, usize)> {
    latest_reg_state_for_instruction(
        states,
        instruction,
        fragment_start_line,
        reg,
        false,
        |state, reg| (reg, state.log_line),
    )
}

pub fn latest_reg_state_before_instruction_with_frame<'a>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
) -> Option<(&'a RegState, usize)> {
    latest_reg_state_for_instruction(
        states,
        instruction,
        fragment_start_line,
        reg,
        false,
        |state, reg| (reg, reg.source_frame.unwrap_or(state.frame)),
    )
}

pub fn latest_verifier_state_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
) -> Option<&'a VerifierInsn> {
    latest_verifier_state_for_instruction(states, instruction, fragment_start_line, false, false)
}

pub fn latest_verifier_state_at_or_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
) -> Option<&'a VerifierInsn> {
    latest_verifier_state_for_instruction(states, instruction, fragment_start_line, true, false)
}

pub fn latest_ref_state_before_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
) -> Option<&'a VerifierInsn> {
    latest_verifier_state_for_instruction(states, instruction, fragment_start_line, false, true)
}

pub fn latest_verifier_state_before(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    terminal_line: Option<usize>,
) -> Option<&VerifierInsn> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .filter(|state| terminal_line.is_none_or(|line| state.log_line < line))
        .next_back()
}

pub fn verifier_path_snapshot_before_instruction(
    states: &[VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start: usize,
) -> Option<PathVerifierSnapshot> {
    let mut snapshot: Option<PathVerifierSnapshot> = None;
    for state in states_in_instruction_window(states, instruction, fragment_start, false) {
        let reset_path = matches!(
            state.kind,
            VerifierInsnKind::EdgeFullState | VerifierInsnKind::PcFullState
        ) || snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.frame != state.frame);
        if reset_path || snapshot.is_none() {
            snapshot = Some(PathVerifierSnapshot {
                frame: state.frame,
                regs: state.regs.clone(),
                stack: state.stack.clone(),
            });
            continue;
        }
        let snapshot = snapshot.as_mut()?;
        snapshot.regs.extend(state.regs.clone());
        snapshot.stack.extend(state.stack.clone());
    }
    snapshot
}

pub fn initialized_stack_bytes_from_snapshot(stack: &HashMap<i16, StackState>, start: i16) -> i16 {
    if start >= 0 {
        return 0;
    }
    let mut initialized = 0i16;
    let mut offset = start;
    while offset < 0 {
        if !stack_byte_initialized_at_offset(stack, offset) {
            break;
        }
        initialized = initialized.saturating_add(1);
        offset = offset.saturating_add(1);
    }
    initialized
}

fn latest_verifier_state_for_instruction<'a>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
    include_instruction: bool,
    refs_only: bool,
) -> Option<&'a VerifierInsn> {
    states_in_instruction_window(
        states,
        instruction,
        fragment_start_line,
        include_instruction,
    )
    .filter(|state| !refs_only || !state.ref_ids.is_empty())
    .next_back()
}

fn latest_reg_state_for_instruction<'a, T>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
    reg: u8,
    include_instruction: bool,
    map: impl Fn(&'a VerifierInsn, &'a RegState) -> T,
) -> Option<T> {
    let call_frame = latest_verifier_state_for_instruction(
        states,
        instruction,
        fragment_start_line,
        include_instruction,
        false,
    )
    .map(|state| state.frame);
    states_in_instruction_window(
        states,
        instruction,
        fragment_start_line,
        include_instruction,
    )
    .filter(|state| call_frame.is_none_or(|frame| state.frame == frame))
    .rev()
    .find_map(|state| state.regs.get(&reg).map(|reg_state| map(state, reg_state)))
}

fn states_in_instruction_window<'a>(
    states: &'a [VerifierInsn],
    instruction: VerifierLogInstruction<'_>,
    fragment_start_line: usize,
    include_instruction: bool,
) -> impl DoubleEndedIterator<Item = &'a VerifierInsn> + 'a {
    let instruction_pc = instruction.pc;
    let instruction_line = instruction.line;
    states.iter().filter(move |state| {
        state.log_line >= fragment_start_line
            && if include_instruction {
                state.log_line <= instruction_line
            } else {
                state.log_line < instruction_line
            }
            && state.pc <= instruction_pc
    })
}

fn stack_byte_initialized_at_offset(
    stack: &HashMap<i16, StackState>,
    absolute_offset: i16,
) -> bool {
    let Some(slot_start) = verifier_stack_slot_start(i32::from(absolute_offset)) else {
        return false;
    };
    stack
        .get(&slot_start)
        .is_some_and(|slot| stack_byte_initialized(slot, slot_start, absolute_offset))
}

fn stack_byte_initialized(stack: &StackState, slot_start: i16, absolute_offset: i16) -> bool {
    if let Some(slot_types) = stack.slot_types.as_deref() {
        let byte_index = absolute_offset.saturating_sub(slot_start);
        let Ok(byte_index) = usize::try_from(byte_index) else {
            return false;
        };
        if byte_index >= 8 {
            return false;
        }
        return slot_types
            .as_bytes()
            .get(7 - byte_index)
            .is_some_and(|slot_type| plain_stack_slot_byte(*slot_type, stack.value.as_ref()));
    }
    stack
        .value
        .as_ref()
        .is_some_and(plain_helper_readable_stack_value)
}

fn plain_stack_slot_byte(slot_type: u8, value: Option<&RegState>) -> bool {
    match slot_type {
        b'0' | b'm' => true,
        b'r' => value.is_some_and(plain_helper_readable_stack_value),
        _ => false,
    }
}

fn plain_helper_readable_stack_value(value: &RegState) -> bool {
    value.reg_type == "scalar"
}

fn parse_instruction_prefix(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start();
    let digits_len = trimmed
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits_len == 0 || trimmed.as_bytes().get(digits_len) != Some(&b':') {
        return None;
    }
    Some((
        trimmed[..digits_len].parse().ok()?,
        trimmed[digits_len + 1..].trim_start(),
    ))
}

fn instruction_opcode_tail(tail: &str) -> Option<&str> {
    if looks_like_opcode_tail(tail) {
        return Some(tail);
    }
    let mask_len = tail.find(char::is_whitespace)?;
    tail[..mask_len]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        .then(|| tail[mask_len..].trim_start())
        .filter(|rest| looks_like_opcode_tail(rest))
}

fn looks_like_opcode_tail(tail: &str) -> bool {
    let bytes = tail.as_bytes();
    bytes.len() >= 4
        && bytes[0] == b'('
        && bytes[1..3].iter().all(u8::is_ascii_hexdigit)
        && bytes[3] == b')'
}

fn parse_register_token(token: &str, allow_w: bool) -> Option<u8> {
    let token = token.trim_end_matches(|ch| matches!(ch, ',' | ';'));
    let digits = token
        .strip_prefix('r')
        .or_else(|| allow_w.then(|| token.strip_prefix('w')).flatten())?;
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

fn parse_signed_decimal(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
pub(crate) fn parse_verifier_log(log: &str) -> Vec<VerifierInsn> {
    parse_verifier_log_result(log).expect("test verifier log should parse")
}
#[cfg(test)]
pub(crate) fn parse_verifier_log_result(log: &str) -> Result<Vec<VerifierInsn>> {
    parse_log_states(log, true)
}
pub fn verifier_states_from_log(log: &str) -> Result<Vec<VerifierInsn>> {
    parse_log_states(log, false)
}

pub fn verifier_states_with_branch_deltas_from_log(log: &str) -> Result<Vec<VerifierInsn>> {
    parse_log_states(log, true)
}

fn parse_log_states(log: &str, include_branch_delta: bool) -> Result<Vec<VerifierInsn>> {
    let mut states = Vec::new();
    for (idx, line) in log.lines().enumerate() {
        let Some(mut state) = parse_state_line(line).with_context(|| {
            format!(
                "failed to parse verifier state line {}: {:?}",
                idx + 1,
                line
            )
        })?
        else {
            continue;
        };
        state.log_line = idx + 1;
        if include_branch_delta || state.kind != VerifierInsnKind::BranchDeltaState {
            states.push(state);
        }
    }
    Ok(states)
}
fn parse_state_line(line: &str) -> Result<Option<VerifierInsn>> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let Some((pc, from_pc, kind, speculative, state_text)) =
        parse_from_state_line(trimmed).or_else(|| parse_pc_state_line(trimmed))
    else {
        if looks_like_state_line(trimmed) {
            bail!("state-like line did not match a supported verifier state format");
        }
        return Ok(None);
    };
    let (frame, state_text) = strip_frame_prefix(state_text);
    let mut regs = HashMap::new();
    let mut stack = HashMap::new();
    let mut refs = None;
    let mut ref_ids = Vec::new();
    let mut callback_kind = None;
    let tokens = split_top_level_tokens(state_text);
    let mut idx = 0usize;
    while idx < tokens.len() {
        let token = tokens[idx];
        if token == "cb" {
            callback_kind = Some(CallbackKind::Sync);
            idx += 1;
            continue;
        }
        if token == "async_cb" {
            callback_kind = Some(CallbackKind::Async);
            idx += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("refs=") {
            refs = parse_refs_value(value);
            ref_ids = parse_ref_ids(value);
            idx += 1;
            continue;
        }
        if let Some((regno, state)) = parse_reg_token(token) {
            regs.insert(regno, state);
            idx += 1;
            continue;
        }
        if let Some((off, mut state)) = parse_stack_token(token) {
            if state.value.is_none()
                && idx + 1 < tokens.len()
                && parse_reg_token(tokens[idx + 1]).is_none()
                && parse_stack_token(tokens[idx + 1]).is_none()
                && looks_like_reg_state(tokens[idx + 1])
            {
                match parse_reg_state(tokens[idx + 1], VerifierValueWidth::Unknown) {
                    Ok(value) => {
                        state.value = Some(value);
                        idx += 1;
                    }
                    Err(err) => {
                        warn_verifier_log(format!("skipping {:?}: {err:#}", tokens[idx + 1]));
                    }
                }
            }
            stack.insert(off, state);
            idx += 1;
            continue;
        }
        idx += 1;
    }
    if regs.is_empty() && stack.is_empty() && refs.is_none() && callback_kind.is_none() {
        bail!("verifier state line contained no register or stack state");
    }
    Ok(Some(VerifierInsn {
        pc,
        log_line: 0,
        frame,
        from_pc,
        kind,
        speculative,
        regs,
        stack,
        refs,
        ref_ids,
        callback_kind,
        callback: callback_kind.is_some(),
    }))
}
fn looks_like_state_line(line: &str) -> bool {
    if line.starts_with("from ") {
        return line.contains(':')
            && (line.contains(" R") || line.contains(": R") || line.contains("frame"));
    }
    let Some((pc, tail)) = line.split_once(':') else {
        return false;
    };
    if !pc.trim().chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    let tail = tail.trim();
    if is_state_text(tail) {
        return true;
    }
    // "<pc>: <insn> ; <state>" — only state-like if the post-`;` segment
    // actually contains register/frame state. Lines like
    // "224: (85) call bpf_tail_call#12       ;" have an empty post-`;`
    // because the verifier emits no state for non-returning instructions.
    tail.split_once(';')
        .map(|(_, state)| is_state_text(state.trim()))
        .unwrap_or(false)
}
fn parse_from_state_line(
    line: &str,
) -> Option<(usize, Option<usize>, VerifierInsnKind, bool, &str)> {
    let rest = line.strip_prefix("from ")?;
    let (from_text, rest) = rest.split_once(" to ")?;
    let from_pc = from_text.trim().parse().ok()?;
    let digits_len = rest.chars().take_while(|ch| ch.is_ascii_digit()).count();
    if digits_len == 0 {
        return None;
    }
    let pc = rest[..digits_len].parse().ok()?;
    let mut tail = &rest[digits_len..];
    let speculative = if let Some(stripped) = tail.strip_prefix(" (speculative execution)") {
        tail = stripped;
        true
    } else {
        false
    };
    let state_text = tail.strip_prefix(':')?.trim();
    is_state_text(state_text).then_some((
        pc,
        Some(from_pc),
        VerifierInsnKind::EdgeFullState,
        speculative,
        state_text,
    ))
}
fn parse_pc_state_line(line: &str) -> Option<(usize, Option<usize>, VerifierInsnKind, bool, &str)> {
    let colon = line.find(':')?;
    let pc = line[..colon].trim().parse().ok()?;
    let tail = line[colon + 1..].trim();
    if tail.is_empty() {
        return None;
    }
    if is_state_text(tail) {
        return Some((pc, None, VerifierInsnKind::PcFullState, false, tail));
    }
    let semicolon = find_top_level_char(tail, ';')?;
    let insn_text = tail[..semicolon].trim();
    let state_text = tail[semicolon + 1..].trim();
    let kind = if insn_text.contains(" if ") && insn_text.contains(" goto ") {
        VerifierInsnKind::BranchDeltaState
    } else {
        VerifierInsnKind::InsnDeltaState
    };
    is_state_text(state_text).then_some((pc, None, kind, false, state_text))
}
fn is_state_text(text: &str) -> bool {
    text.starts_with('R')
        || text.starts_with("frame")
        || text.starts_with("fp-")
        || text.starts_with("refs=")
        || matches!(text, "cb" | "async_cb")
}
fn strip_frame_prefix(text: &str) -> (usize, &str) {
    let Some(rest) = text.strip_prefix("frame") else {
        return (0, text);
    };
    let digits_len = rest.chars().take_while(|ch| ch.is_ascii_digit()).count();
    if digits_len == 0 {
        return (0, text);
    }
    let frame = rest[..digits_len].parse().ok();
    let tail = rest[digits_len..].trim_start();
    match (frame, tail.strip_prefix(':')) {
        (Some(frame), Some(tail)) => (frame, tail.trim_start()),
        _ => (0, text),
    }
}

fn parse_refs_value(value: &str) -> Option<u32> {
    value.parse().ok().or_else(|| {
        let count = value
            .split(',')
            .filter(|item| !item.is_empty() && item.bytes().all(|byte| byte.is_ascii_digit()))
            .count();
        (count > 0 && value.split(',').count() == count)
            .then(|| count.try_into().ok())
            .flatten()
    })
}

fn parse_ref_ids(value: &str) -> Vec<u32> {
    let mut ids = Vec::new();
    for item in value.split(',') {
        let Ok(id) = item.parse() else {
            return Vec::new();
        };
        if id == 0 {
            return Vec::new();
        }
        ids.push(id);
    }
    ids
}

fn split_top_level_tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start = None;
    let mut depth = 0i32;
    for (idx, ch) in text.char_indices() {
        match ch {
            '(' => {
                if start.is_none() {
                    start = Some(idx);
                }
                depth += 1;
            }
            ')' => {
                depth -= 1;
            }
            ch if ch.is_whitespace() && depth == 0 => {
                if let Some(token_start) = start.take() {
                    tokens.push(&text[token_start..idx]);
                }
            }
            _ => {
                if start.is_none() {
                    start = Some(idx);
                }
            }
        }
    }
    if let Some(token_start) = start {
        tokens.push(&text[token_start..]);
    }
    tokens
}
fn parse_reg_token(token: &str) -> Option<(u8, RegState)> {
    let (lhs, rhs) = token.split_once('=')?;
    let Some((regno, value_width)) = parse_reg_name(lhs) else {
        if lhs.starts_with('R') {
            warn_verifier_log(format!("invalid register token {token:?}"));
        }
        return None;
    };
    match parse_reg_state(rhs.trim(), value_width) {
        Ok(state) => Some((regno, state)),
        Err(err) => {
            warn_verifier_log(format!("skipping {token:?}: {err:#}"));
            None
        }
    }
}
fn parse_stack_token(token: &str) -> Option<(i16, StackState)> {
    let (lhs, rhs) = token.split_once('=')?;
    let fp_off = lhs.strip_prefix("fp")?;
    let fp_off = strip_stack_access_suffix(fp_off);
    let Some(off) = parse_i32(fp_off).and_then(|off| off.try_into().ok()) else {
        warn_verifier_log(format!("invalid stack offset in {token:?}"));
        return None;
    };
    match parse_stack_state(rhs.trim()) {
        Ok(state) => Some((off, state)),
        Err(err) => {
            warn_verifier_log(format!("skipping {token:?}: {err:#}"));
            None
        }
    }
}

fn strip_stack_access_suffix(offset: &str) -> &str {
    offset
        .strip_suffix("_rw")
        .or_else(|| offset.strip_suffix("_r"))
        .or_else(|| offset.strip_suffix("_w"))
        .unwrap_or(offset)
}

fn parse_reg_name(name: &str) -> Option<(u8, VerifierValueWidth)> {
    let name = name.strip_prefix('R')?;
    let (name, value_width) = if let Some(name) = name.strip_suffix("_w") {
        (name, VerifierValueWidth::Bits32)
    } else {
        (name, VerifierValueWidth::Bits64)
    };
    Some((name.parse().ok()?, value_width))
}
fn parse_reg_state(raw: &str, value_width: VerifierValueWidth) -> Result<RegState> {
    let (precise, value) = match raw.strip_prefix('P') {
        Some(rest) => (true, rest),
        None => (false, raw),
    };
    if let Some(exact) = parse_scalar_exact_value(value) {
        let mut state = RegState::new("scalar", value_width);
        state.precise = precise;
        state.exact_value = Some(exact);
        apply_exact_value_to_range(&mut state.range, exact, value_width);
        return Ok(state);
    }
    if let Some(rest) = value
        .strip_prefix("fp")
        .filter(|rest| !rest.starts_with('('))
    {
        let mut state = RegState::new("fp", value_width);
        state.precise = precise;
        // Cross-frame form `fp[N]-M`: the kernel verifier annotates the source
        // frame for stack pointers, which callers need to avoid confusing a
        // parent-frame stack slot with the current frame.
        let offset_text = match rest.strip_prefix('[').and_then(|r| r.split_once(']')) {
            Some((frame, after)) => {
                state.source_frame = Some(
                    frame
                        .parse()
                        .map_err(|_| anyhow!("invalid frame-pointer source frame {frame:?}"))?,
                );
                after
            }
            None => rest,
        };
        if !offset_text.is_empty() {
            state.offset = Some(
                parse_i32(offset_text)
                    .ok_or_else(|| anyhow!("invalid frame-pointer offset {offset_text:?}"))?,
            );
        }
        return Ok(state);
    }
    if let Some(open) = value.find('(') {
        let close = value
            .rfind(')')
            .ok_or_else(|| anyhow!("missing ')' in verifier register state {value:?}"))?;
        let reg_type = normalize_reg_type(&value[..open]);
        let mut state = RegState::new(reg_type, value_width);
        state.precise = precise;
        parse_reg_attributes(&value[open + 1..close], &mut state);
        infer_exact_value(&mut state);
        return Ok(state);
    }
    let mut state = RegState::new(normalize_reg_type(value), value_width);
    state.precise = precise;
    Ok(state)
}
fn normalize_reg_type(reg_type: &str) -> String {
    match reg_type {
        "inv" => "scalar".to_string(),
        other => other.to_string(),
    }
}
fn parse_stack_state(raw: &str) -> Result<StackState> {
    if raw.is_empty() {
        return Ok(StackState {
            slot_types: None,
            value: None,
        });
    }
    for split in raw.char_indices().skip(1).map(|(idx, _)| idx) {
        let prefix = &raw[..split];
        let rest = raw[split..].trim();
        if prefix.len() == 8
            && prefix.chars().all(is_stack_slot_type_char)
            && looks_like_reg_state(rest)
        {
            return Ok(StackState {
                slot_types: Some(prefix.to_string()),
                value: Some(parse_reg_state(rest, VerifierValueWidth::Unknown)?),
            });
        }
    }
    if raw.len() == 8 && raw.chars().all(is_stack_slot_type_char) {
        return Ok(StackState {
            slot_types: Some(raw.to_string()),
            value: None,
        });
    }
    if looks_like_reg_state(raw) {
        return Ok(StackState {
            slot_types: None,
            value: Some(parse_reg_state(raw, VerifierValueWidth::Unknown)?),
        });
    }
    if raw.chars().all(is_stack_slot_type_char) {
        return Ok(StackState {
            slot_types: Some(raw.to_string()),
            value: None,
        });
    }
    Ok(StackState {
        slot_types: None,
        value: Some(parse_reg_state(raw, VerifierValueWidth::Unknown)?),
    })
}
fn looks_like_reg_state(raw: &str) -> bool {
    if raw.is_empty() {
        return false;
    }
    parse_signed_value(raw).is_some()
        || raw.starts_with("fp")
        || raw.contains('(')
        || raw == "scalar"
        || (!raw.chars().all(is_stack_slot_type_char)
            && raw
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '+' | '-')))
}
fn is_stack_slot_type_char(ch: char) -> bool {
    matches!(ch, '?' | 'r' | 'm' | '0' | 'd' | 'i' | 'f')
}
fn parse_reg_attributes(attrs: &str, state: &mut RegState) {
    for segment in split_top_level_segments(attrs, ',') {
        let parts: Vec<_> = segment
            .split('=')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect();
        if parts.len() == 1 {
            match parts[0] {
                "trusted" | "untrusted" | "rdonly_buf" | "rdwr_buf" | "rcu" | "percpu_ptr"
                | "may_be_null" | "alloc" => continue,
                other => {
                    warn_verifier_log(format!("unknown verifier register attribute {other:?}"));
                    continue;
                }
            }
        }
        if parts.len() < 2 {
            warn_verifier_log(format!(
                "malformed verifier register attribute segment {segment:?}"
            ));
            continue;
        }
        let value = parts[parts.len() - 1];
        for key in &parts[..parts.len() - 1] {
            match *key {
                "smin" | "smin_value" => {
                    state.range.smin = parse_attr(key, value, parse_signed_value(value));
                }
                "smax" | "smax_value" => {
                    state.range.smax = parse_attr(key, value, parse_signed_value(value));
                }
                "umin" | "umin_value" => {
                    state.range.umin = parse_attr(key, value, parse_unsigned_value(value));
                }
                "umax" | "umax_value" => {
                    state.range.umax = parse_attr(key, value, parse_unsigned_value(value));
                }
                "smin32" | "smin32_value" => {
                    state.range.smin32 = parse_attr(key, value, parse_i32(value));
                }
                "smax32" | "smax32_value" => {
                    state.range.smax32 = parse_attr(key, value, parse_i32(value));
                }
                "umin32" | "umin32_value" => {
                    state.range.umin32 = parse_attr(key, value, parse_u32(value));
                }
                "umax32" | "umax32_value" => {
                    state.range.umax32 = parse_attr(key, value, parse_u32(value));
                }
                "off" => state.offset = parse_attr(key, value, parse_i32(value)),
                "r" => state.packet_range = parse_attr(key, value, parse_u32(value)),
                "vs" => state.map_value_size = parse_attr(key, value, parse_u32(value)),
                "sz" | "mem_size" => state.mem_size = parse_attr(key, value, parse_u32(value)),
                "id" => state.id = parse_attr(key, value, parse_u32(value)),
                "ref_id" => state.ref_id = parse_attr(key, value, parse_u32(value)),
                "var_off" => {
                    state.tnum = parse_attr(key, value, parse_tnum(value));
                }
                "map" | "ks" | "imm" | "ref_obj_id" | "btf_id" | "alloc_size" | "aux_off"
                | "name" | "dynptr_id" => {}
                other => {
                    warn_verifier_log(format!("unknown verifier register attribute {other:?}"));
                }
            }
        }
    }
}

fn warn_verifier_log(message: String) {
    if std::env::var_os("BPFANALYSIS_WARN_VERIFIER_LOG").is_some() {
        eprintln!("warning: verifier log: {message}");
    }
}
fn parse_attr<T>(key: &str, value: &str, parsed: Option<T>) -> Option<T> {
    if parsed.is_none() {
        warn_verifier_log(format!("invalid {key} attribute value {value:?}"));
    }
    parsed
}
fn apply_exact_value_to_range(
    range: &mut ScalarRange,
    exact: u64,
    value_width: VerifierValueWidth,
) {
    let exact32 = exact as u32;
    range.umin32 = Some(exact32);
    range.umax32 = Some(exact32);
    range.smin32 = Some(exact32 as i32);
    range.smax32 = Some(exact32 as i32);
    if value_width != VerifierValueWidth::Bits32 {
        range.umin = Some(exact);
        range.umax = Some(exact);
        range.smin = Some(exact as i64);
        range.smax = Some(exact as i64);
    }
}
fn infer_exact_value(state: &mut RegState) {
    if state.reg_type != "scalar" || state.exact_value.is_some() {
        return;
    }
    if let Some(tnum) = state.tnum {
        if tnum.mask == 0 {
            state.exact_value = Some(tnum.value);
            return;
        }
    }
    if let (Some(umin), Some(umax)) = (state.range.umin, state.range.umax) {
        if umin == umax {
            state.exact_value = Some(umin);
            return;
        }
    }
    if let (Some(umin32), Some(umax32)) = (state.range.umin32, state.range.umax32) {
        if umin32 == umax32 {
            state.exact_value = Some(u64::from(umin32));
            if state.value_width == VerifierValueWidth::Bits64 {
                state.value_width = VerifierValueWidth::Bits32;
            }
        }
    }
}
fn split_top_level_segments(text: &str, separator: char) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    for (idx, ch) in text.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ if ch == separator && depth == 0 => {
                let segment = text[start..idx].trim();
                if !segment.is_empty() {
                    segments.push(segment);
                }
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    let segment = text[start..].trim();
    if !segment.is_empty() {
        segments.push(segment);
    }
    segments
}
fn find_top_level_char(text: &str, needle: char) -> Option<usize> {
    let mut depth = 0i32;
    for (idx, ch) in text.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ if ch == needle && depth == 0 => return Some(idx),
            _ => {}
        }
    }
    None
}
fn parse_i32(text: &str) -> Option<i32> {
    parse_signed_value(text)?.try_into().ok()
}
fn parse_u32(text: &str) -> Option<u32> {
    parse_unsigned_u64(text)?.try_into().ok()
}
fn parse_hex_u64(text: &str) -> Option<u64> {
    u64::from_str_radix(text, 16).ok()
}
fn parse_signed_value(text: &str) -> Option<i64> {
    let value = text.trim();
    let (negative, body) = match value.as_bytes().first()? {
        b'-' => (true, &value[1..]),
        b'+' => (false, &value[1..]),
        _ => (false, value),
    };
    if let Some(rest) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        let mag = parse_hex_u64(rest)?;
        if negative {
            return i64::try_from(-(mag as i128)).ok();
        }
        return Some(mag as i64);
    }
    if negative {
        value.parse::<i64>().ok()
    } else {
        body.parse().ok()
    }
}
fn parse_unsigned_value(text: &str) -> Option<u64> {
    let value = text.trim();
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    if let Some(rest) = value.strip_prefix('+') {
        parse_unsigned_u64(rest)
    } else {
        parse_unsigned_u64(value)
    }
}
fn parse_unsigned_u64(text: &str) -> Option<u64> {
    if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return parse_hex_u64(rest);
    }
    text.parse().ok()
}
fn parse_scalar_exact_value(text: &str) -> Option<u64> {
    let value = text.trim();
    if value.is_empty() || value.contains('(') {
        return None;
    }
    if let Some(rest) = value
        .strip_prefix("-0x")
        .or_else(|| value.strip_prefix("-0X"))
    {
        let magnitude = parse_hex_u64(rest)?;
        return Some(0u64.wrapping_sub(magnitude));
    }
    if let Some(rest) = value.strip_prefix('-') {
        let magnitude = rest.parse().ok()?;
        return Some(0u64.wrapping_sub(magnitude));
    }
    if let Some(rest) = value.strip_prefix('+') {
        return parse_unsigned_u64(rest);
    }
    parse_unsigned_u64(value)
}
fn parse_tnum(text: &str) -> Option<Tnum> {
    let value = text.trim();
    let inner = value.strip_prefix('(')?.strip_suffix(')')?;
    let (value, mask) = inner.split_once(';')?;
    Some(Tnum {
        value: parse_unsigned_u64(value.trim())?,
        mask: parse_unsigned_u64(mask.trim())?,
    })
}
#[cfg(test)]
#[path = "verifier_log_tests.rs"]
mod tests;

// ==========================================================================
// Verifier-state interpretation helpers (formerly analysis/verifier_facts.rs).
//
// Public query functions take an already-resolved slice of `VerifierInsn`
// (one site's visits). Storage lives inline on `InsnNode`/`BasicBlock`; the
// site-to-state lookup happens in `ProgramCFG::verifier_states_at`.
// ==========================================================================

#[cfg(feature = "analysis")]
use crate::analysis::InsnSite;
#[cfg(feature = "analysis")]
use crate::pass::RegKind;
#[cfg(feature = "analysis")]
use std::collections::BTreeMap;
#[cfg(feature = "analysis")]
use std::sync::Arc;

/// Lift-time mapping from site to verifier states. After lift, per-site
/// states live on `InsnNode`/`BasicBlock`; this alias survives only at the
/// lift boundary.
#[cfg(feature = "analysis")]
pub(crate) type VerifierStatesBySite = BTreeMap<InsnSite, Arc<[VerifierInsn]>>;

pub(crate) fn reg_known_constant(
    states: Option<&[VerifierInsn]>,
    reg: u8,
    is_32: bool,
) -> Option<i64> {
    // Use only InsnDeltaState (the per-PC post-state line) — for an ALU op
    // at PC, the verifier post-state captures the *result*, while
    // PcFullState/EdgeFullState capture pre-state on entry. Mixing pre and
    // post would substitute a stale value for the ALU's destination.
    let mut iter = verifier_post_insn_reg_states(states, reg)?;
    let first = reg_exact_value_for_width(iter.next()?, is_32)?;
    for state in iter {
        if reg_exact_value_for_width(state, is_32)? != first {
            return None;
        }
    }
    Some(first as i64)
}

#[cfg(feature = "analysis")]
pub(crate) fn reg_kind(states: Option<&[VerifierInsn]>, reg: u8) -> Option<RegKind> {
    let mut iter = verifier_reg_states(states, reg)?;
    let first = reg_kind_from_verifier_type(&iter.next()?.reg_type);
    for state in iter {
        if reg_kind_from_verifier_type(&state.reg_type) != first {
            return None;
        }
    }
    Some(first)
}

pub(crate) fn reg_known_stack_bytes(
    states: Option<&[VerifierInsn]>,
    reg: u8,
    key_width: usize,
) -> Option<Vec<u8>> {
    let states = states?;
    if states.is_empty()
        || states
            .iter()
            .any(|state| state.kind == VerifierInsnKind::EdgeFullState)
    {
        return None;
    }
    let mut first = None;
    for state in states {
        let reg_state = state.regs.get(&reg)?;
        let stack_off = fp_stack_offset_from_reg_state(reg_state)?;
        let bytes = known_stack_bytes_from_state(state, stack_off, key_width)?;
        match &first {
            Some(existing) if existing != &bytes => return None,
            Some(_) => {}
            None => first = Some(bytes),
        }
    }
    first
}

pub(crate) fn site_is_dead_code(states: Option<&[VerifierInsn]>) -> bool {
    states.is_some_and(|states| !states.is_empty() && states.iter().all(|s| s.speculative))
}

fn verifier_reg_states(
    states: Option<&[VerifierInsn]>,
    reg: u8,
) -> Option<impl Iterator<Item = &RegState>> {
    let states = states?;
    if states.is_empty()
        || states
            .iter()
            .any(|state| state.kind == VerifierInsnKind::EdgeFullState)
    {
        return None;
    }
    if states.iter().any(|state| !state.regs.contains_key(&reg)) {
        return None;
    }
    Some(states.iter().filter_map(move |state| state.regs.get(&reg)))
}

fn verifier_post_insn_reg_states(
    states: Option<&[VerifierInsn]>,
    reg: u8,
) -> Option<impl Iterator<Item = &RegState>> {
    let states = states?;
    let post_states = states
        .iter()
        .filter(|state| state.kind == VerifierInsnKind::InsnDeltaState)
        .collect::<Vec<_>>();
    if post_states.is_empty()
        || post_states
            .iter()
            .any(|state| !state.regs.contains_key(&reg))
    {
        return None;
    }
    Some(
        post_states
            .into_iter()
            .filter_map(move |state| state.regs.get(&reg)),
    )
}

fn reg_exact_value(state: &RegState) -> Option<u64> {
    state.exact_scalar_value()
}

fn reg_exact_value_for_width(state: &RegState, is_32: bool) -> Option<u64> {
    if is_32 {
        state.exact_u32().map(u64::from)
    } else {
        state.exact_u64()
    }
}

fn fp_stack_offset_from_reg_state(state: &RegState) -> Option<i32> {
    (state.reg_type == "fp").then(|| state.offset.unwrap_or(0))
}

fn known_stack_bytes_from_state(
    state: &VerifierInsn,
    stack_off: i32,
    width: usize,
) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(width);
    for idx in 0..width {
        let idx = match i32::try_from(idx) {
            Ok(idx) => idx,
            Err(_) => return None,
        };
        bytes.push(known_stack_byte_from_state(
            state,
            stack_off.checked_add(idx)?,
        )?);
    }
    Some(bytes)
}

fn known_stack_byte_from_state(state: &VerifierInsn, absolute_off: i32) -> Option<u8> {
    let slot_start = verifier_stack_slot_start(absolute_off)?;
    let byte_index = usize::try_from(absolute_off - i32::from(slot_start)).ok()?;
    if byte_index >= 8 {
        return None;
    }
    let stack = state.stack.get(&slot_start)?;
    match verifier_stack_slot_type(stack, byte_index) {
        Some(b'0') => Some(0),
        Some(b'r') | None => verifier_stack_slot_exact_bytes(stack).map(|bytes| bytes[byte_index]),
        Some(_) => None,
    }
}

fn verifier_stack_slot_start(absolute_off: i32) -> Option<i16> {
    if absolute_off >= 0 {
        return None;
    }
    let slot_index = ((-absolute_off - 1) / 8) + 1;
    i16::try_from(-slot_index * 8).ok()
}

fn verifier_stack_slot_type(stack: &StackState, byte_index: usize) -> Option<u8> {
    let slot_types = stack.slot_types.as_ref()?;
    if byte_index >= 8 {
        return None;
    }
    slot_types.as_bytes().get(7 - byte_index).copied()
}

fn verifier_stack_slot_exact_bytes(stack: &StackState) -> Option<[u8; 8]> {
    let value = reg_exact_value(stack.value.as_ref()?)?;
    Some(value.to_le_bytes())
}

#[cfg(feature = "analysis")]
fn reg_kind_from_verifier_type(reg_type: &str) -> RegKind {
    match reg_type {
        "scalar" => RegKind::Scalar,
        "fp" => RegKind::FramePointer,
        "ctx" => RegKind::Context,
        "pkt" => RegKind::PacketPointer,
        "pkt_meta" => RegKind::PacketMetaPointer,
        "map_ptr" => RegKind::MapPointer,
        "map_value" => RegKind::MapValue,
        "map_key" => RegKind::MapKey,
        "mem" | "buf" | "ringbuf_mem" | "iter" => RegKind::Memory,
        other if other.starts_with("scalar") => RegKind::Scalar,
        other if other.starts_with("fp") => RegKind::FramePointer,
        "" => RegKind::Unknown,
        other if other.contains("ptr_") || other.contains("_ptr") => RegKind::BtfStructPointer,
        _ => RegKind::OtherPointer,
    }
}
