use super::{
    parse_i64_after, parse_signed_decimal, parse_u32_after, stack_value_range, StackByteRange,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackReadAccess {
    pub reg: Option<u8>,
    pub base_off: i64,
    pub delta: i64,
    pub size: u64,
}

impl StackReadAccess {
    pub fn range(self) -> Option<StackByteRange> {
        let start = self.base_off.checked_add(self.delta)?;
        StackByteRange::new(
            i16::try_from(start).ok()?,
            i16::try_from(start.checked_add(i64::try_from(self.size).ok()?)?).ok()?,
        )
    }
}

pub fn stack_access_range(message: &str) -> Option<StackByteRange> {
    stack_read_access(message).and_then(StackReadAccess::range)
}

pub fn stack_read_access(message: &str) -> Option<StackReadAccess> {
    message.split(';').find_map(parse_stack_read_access_segment)
}

/// Parses a terminal `invalid write to stack` verifier error into a half-open
/// stack byte range.
pub fn stack_write_access_range(message: &str) -> Option<StackByteRange> {
    message
        .to_ascii_lowercase()
        .contains("invalid write to stack")
        .then(|| {
            let offset = parse_i64_after(message, "off=")
                .or_else(|| parse_i64_after(message, "off "))
                .and_then(|value| i16::try_from(value).ok())?;
            let size = parse_i64_after(message, "size=")
                .or_else(|| parse_i64_after(message, "size "))
                .and_then(|value| i16::try_from(value).ok())?;
            stack_value_range(offset, size)
        })
        .flatten()
}

fn parse_stack_read_access_segment(segment: &str) -> Option<StackReadAccess> {
    let tokens = segment.split_whitespace().collect::<Vec<_>>();
    for start in 0..tokens.len().saturating_sub(3) {
        if tokens[start..start + 4] != ["invalid", "read", "from", "stack"] {
            continue;
        }
        let cursor = start + 4;
        let (reg, off_idx) = if tokens.get(cursor) == Some(&"off") {
            (None, cursor)
        } else if tokens.get(cursor + 1) == Some(&"off") {
            (
                Some(tokens[cursor].strip_prefix('R')?.parse().ok()?),
                cursor + 1,
            )
        } else {
            continue;
        };
        let size_idx = off_idx + 2;
        if tokens.get(size_idx) != Some(&"size") {
            continue;
        }
        let (base_off, delta) = parse_stack_offset_delta(tokens.get(off_idx + 1)?)?;
        return Some(StackReadAccess {
            reg,
            base_off,
            delta,
            size: tokens.get(size_idx + 1)?.parse().ok()?,
        });
    }
    None
}

fn parse_stack_offset_delta(expression: &str) -> Option<(i64, i64)> {
    let split = expression
        .char_indices()
        .skip(1)
        .find_map(|(idx, ch)| matches!(ch, '+' | '-').then_some(idx));
    let Some(split) = split else {
        return Some((expression.parse().ok()?, 0));
    };
    Some((
        expression[..split].parse().ok()?,
        expression[split..].parse().ok()?,
    ))
}

pub fn terminal_required_return_range(message: &str) -> Option<(i64, i64)> {
    let (_, rest) = message.split_once("should have been in [")?;
    let (range, _) = rest.split_once(']')?;
    let (lo, hi) = range.split_once(',')?;
    Some((parse_signed_decimal(lo)?, parse_signed_decimal(hi)?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapValueAccessError {
    pub value_size: u32,
    pub offset: i64,
    pub size: u32,
}

impl MapValueAccessError {
    pub fn end(self) -> Option<i64> {
        self.offset.checked_add(i64::from(self.size))
    }

    pub fn exceeds_value_size(self) -> bool {
        self.end()
            .is_some_and(|end| end > i64::from(self.value_size))
    }

    pub fn access_is_wider_than_value(self) -> bool {
        self.size > self.value_size
    }
}

pub fn map_value_access_error(message: &str) -> Option<MapValueAccessError> {
    if !message
        .to_ascii_lowercase()
        .contains("invalid access to map value")
    {
        return None;
    }
    Some(MapValueAccessError {
        value_size: parse_u32_after(message, "value_size=")?,
        offset: parse_i64_after(message, "off=")?,
        size: parse_u32_after(message, "size=")?,
    })
}

pub fn register_from_verifier_error(message: &str) -> Option<u8> {
    let bytes = message.as_bytes();
    let mut idx = 0usize;
    while idx + 1 < bytes.len() {
        if bytes[idx] != b'R' || !bytes[idx + 1].is_ascii_digit() {
            idx += 1;
            continue;
        }
        let start = idx + 1;
        let mut end = start + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        return message[start..end].parse().ok();
    }
    None
}

/// Parses a verifier terminal argument number from forms such as `arg #1`,
/// `arg#1`, or `arg 1`.
///
/// This reports the number printed by the verifier; it does not convert between
/// helper ABI argument numbering and BPF registers.
pub fn arg_number_from_verifier_error(message: &str) -> Option<u32> {
    parse_u32_after(message, "arg #")
        .or_else(|| parse_u32_after(message, "arg#"))
        .or_else(|| parse_u32_after(message, "arg "))
}

/// Parses zero-based verifier call-slot indices from markers such as `arg#` or
/// `args#`.
///
/// Do not use this for one-based messages such as `helper arg1`; those already
/// name the BPF helper argument register directly.
pub fn zero_based_arg_index_after(message: &str, marker: &str) -> Option<u32> {
    let arg = parse_u32_after(message, marker)?;
    (arg < 5).then_some(arg)
}

/// Converts a zero-based verifier call-slot index to the corresponding helper
/// argument register (`arg#0` maps to R1).
pub fn register_for_zero_based_arg_index(arg: u32) -> Option<u8> {
    (arg < 5).then(|| (arg + 1) as u8)
}

/// Parses a zero-based `arg#`/`args#` verifier call-slot and returns its helper
/// argument register.
///
/// Do not use this for one-based `helper argN` messages.
pub fn zero_based_arg_register_after(message: &str, marker: &str) -> Option<u8> {
    register_for_zero_based_arg_index(zero_based_arg_index_after(message, marker)?)
}

/// Parses the helper token printed in terminal verifier errors.
///
/// The returned token may include the verifier helper id suffix, for example
/// `bpf_probe_read#4`.
pub fn helper_name_from_verifier_error(message: &str) -> Option<String> {
    for marker in ["cannot use helper ", "helper call ", "unknown func "] {
        let Some(start) = message.find(marker).map(|idx| idx + marker.len()) else {
            continue;
        };
        let helper = message[start..]
            .split_whitespace()
            .next()?
            .trim_matches(|ch: char| ch == ':' || ch == ',' || ch == ';')
            .to_string();
        if !helper.is_empty() {
            return Some(helper);
        }
    }
    None
}
