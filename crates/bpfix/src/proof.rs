use bpfanalysis::{RegState, VerifierInsn};

use crate::family::ProofObligation;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredProof {
    pub obligation: ProofObligation,
    pub register: Option<u8>,
    pub description: String,
    pub rejection_detail: String,
}

pub(crate) fn instantiate_required_proof(
    terminal_error: &str,
    terminal_pc: Option<usize>,
    states: &[VerifierInsn],
) -> RequiredProof {
    let obligation = infer_obligation(terminal_error);
    let register = parse_register_from_error(terminal_error);
    match obligation {
        ProofObligation::PacketBounds => packet_bounds_required_proof(terminal_error, register),
        ProofObligation::ScalarRange => {
            scalar_range_required_proof(terminal_error, terminal_pc, states, register)
        }
        ProofObligation::NullablePointer => nullable_required_proof(terminal_error, register),
        ProofObligation::StackInitialized => stack_required_proof(terminal_error, register),
        ProofObligation::ReferenceLifecycle => reference_required_proof(terminal_error, register),
        ProofObligation::EnvironmentCapability => environment_required_proof(terminal_error),
        _ => RequiredProof {
            obligation,
            register,
            description: obligation.default_required_proof().to_string(),
            rejection_detail: obligation.rejected_detail().to_string(),
        },
    }
}

fn packet_bounds_required_proof(message: &str, register: Option<u8>) -> RequiredProof {
    let off = parse_i64_after(message, "off=");
    let size = parse_i64_after(message, "size=");
    let proven_range = parse_i64_after(message, "r=");
    let required_end = off.zip(size).map(|(off, size)| off.saturating_add(size));
    let description = match (register, required_end, proven_range) {
        (Some(reg), Some(required), Some(range)) => format!(
            "prove R{reg} has packet range at least {required} bytes before this access; verifier currently has range {range}"
        ),
        (Some(reg), Some(required), None) => {
            format!("prove R{reg} has packet range at least {required} bytes before this access")
        }
        _ => ProofObligation::PacketBounds
            .default_required_proof()
            .to_string(),
    };
    let rejection_detail = match (register, required_end, proven_range) {
        (Some(reg), Some(required), Some(range)) => format!(
            "rejected here: verifier needs R{reg} packet range >= {required}, but only {range} bytes are proven"
        ),
        (Some(reg), Some(required), None) => format!(
            "rejected here: verifier needs R{reg} packet range >= {required} before this access"
        ),
        _ => ProofObligation::PacketBounds.rejected_detail().to_string(),
    };
    RequiredProof {
        obligation: ProofObligation::PacketBounds,
        register,
        description,
        rejection_detail,
    }
}

fn scalar_range_required_proof(
    message: &str,
    terminal_pc: Option<usize>,
    states: &[VerifierInsn],
    register: Option<u8>,
) -> RequiredProof {
    let register = register.or_else(|| latest_scalar_register(states, terminal_pc));
    let state = register.and_then(|reg| latest_reg_state(states, terminal_pc, reg));
    let description = if message.contains("value -") {
        "prove the scalar used for pointer arithmetic cannot be negative on any path".to_string()
    } else {
        match (register, state) {
            (Some(reg), Some(state)) => format!(
                "prove R{reg} has a bounded non-negative scalar range before this pointer arithmetic or helper memory access; verifier sees {}",
                scalar_range_summary(state)
            ),
            (Some(reg), None) => {
                format!("prove R{reg} has a bounded non-negative scalar range before this pointer arithmetic or helper memory access")
            }
            _ => ProofObligation::ScalarRange
                .default_required_proof()
                .to_string(),
        }
    };
    let rejection_detail = match (register, state) {
        (Some(reg), Some(state)) => format!(
            "rejected here: verifier still sees R{reg} as {}",
            scalar_range_summary(state)
        ),
        (Some(reg), None) => {
            format!("rejected here: R{reg} is not proven to have a safe scalar range")
        }
        (None, _) => ProofObligation::ScalarRange.rejected_detail().to_string(),
    };
    RequiredProof {
        obligation: ProofObligation::ScalarRange,
        register,
        description,
        rejection_detail,
    }
}

fn nullable_required_proof(message: &str, register: Option<u8>) -> RequiredProof {
    let description = match register {
        Some(reg) => {
            format!("prove R{reg} is non-null in the same verifier-visible branch before dereference, pointer arithmetic, or helper reuse")
        }
        None => ProofObligation::NullablePointer
            .default_required_proof()
            .to_string(),
    };
    let rejection_detail = match register {
        Some(reg) if message.contains("pointer arithmetic") => {
            format!("rejected here: R{reg} is still nullable, so pointer arithmetic is prohibited")
        }
        Some(reg) => format!("rejected here: R{reg} is still nullable at the use site"),
        None => ProofObligation::NullablePointer
            .rejected_detail()
            .to_string(),
    };
    RequiredProof {
        obligation: ProofObligation::NullablePointer,
        register,
        description,
        rejection_detail,
    }
}

fn stack_required_proof(message: &str, register: Option<u8>) -> RequiredProof {
    let description = match register {
        Some(reg) if message.contains("!read_ok") => {
            format!(
                "write a readable value to R{reg} on every path before this return or helper use"
            )
        }
        Some(reg) => {
            format!("initialize every stack byte reachable from R{reg} before it is read or passed to a helper")
        }
        None => ProofObligation::StackInitialized
            .default_required_proof()
            .to_string(),
    };
    let rejection_detail = match register {
        Some(reg) if message.contains("!read_ok") => {
            format!("rejected here: R{reg} is not readable on this path")
        }
        Some(reg) => {
            format!("rejected here: stack memory reachable from R{reg} is not fully initialized")
        }
        None => ProofObligation::StackInitialized
            .rejected_detail()
            .to_string(),
    };
    RequiredProof {
        obligation: ProofObligation::StackInitialized,
        register,
        description,
        rejection_detail,
    }
}

fn reference_required_proof(message: &str, register: Option<u8>) -> RequiredProof {
    let ref_id =
        parse_i64_after(message, "id=").or_else(|| parse_i64_after(message, "ref_obj_id="));
    let description = match ref_id {
        Some(id) => format!("release verifier-tracked reference id {id} on every path before exit"),
        None => ProofObligation::ReferenceLifecycle
            .default_required_proof()
            .to_string(),
    };
    let rejection_detail = match ref_id {
        Some(id) => format!("rejected here: reference id {id} is not released on every path"),
        None => ProofObligation::ReferenceLifecycle
            .rejected_detail()
            .to_string(),
    };
    RequiredProof {
        obligation: ProofObligation::ReferenceLifecycle,
        register,
        description,
        rejection_detail,
    }
}

fn environment_required_proof(message: &str) -> RequiredProof {
    let helper = parse_helper_name(message);
    let description = match helper.as_deref() {
        Some(helper) => format!(
            "load this program with an attach type and kernel environment that allow {helper}, or avoid that helper on this path"
        ),
        None => ProofObligation::EnvironmentCapability
            .default_required_proof()
            .to_string(),
    };
    let rejection_detail = match helper {
        Some(helper) => format!("rejected here: this program type cannot use {helper}"),
        None => ProofObligation::EnvironmentCapability
            .rejected_detail()
            .to_string(),
    };
    RequiredProof {
        obligation: ProofObligation::EnvironmentCapability,
        register: parse_register_from_error(message),
        description,
        rejection_detail,
    }
}

pub(crate) fn infer_obligation(message: &str) -> ProofObligation {
    let lower = message.to_ascii_lowercase();
    if lower.contains("invalid access to packet") || lower.contains("outside of the packet") {
        return ProofObligation::PacketBounds;
    }
    if lower.contains("invalid access to map value") {
        return ProofObligation::ScalarRange;
    }
    if lower.contains("map_value_or_null")
        || lower.contains("ptr_or_null")
        || lower.contains("mem_or_null")
        || lower.contains("possibly null")
    {
        return ProofObligation::NullablePointer;
    }
    if lower.contains("invalid read from stack")
        || lower.contains("invalid indirect read from stack")
        || lower.contains("uninitialized")
        || lower.contains("r0 !read_ok")
    {
        return ProofObligation::StackInitialized;
    }
    if lower.contains("unreleased reference") || lower.contains("reference has not been released") {
        return ProofObligation::ReferenceLifecycle;
    }
    if lower.contains("unbounded")
        || lower.contains("min value is negative")
        || lower.contains("out of bounds")
        || lower.contains("invalid access to map value")
        || lower.contains("invalid zero-sized")
        || lower.contains("makes pkt pointer")
        || lower.contains("outside of allowed memory range")
        || lower.contains("invalid variable-offset")
    {
        return ProofObligation::ScalarRange;
    }
    if lower.contains("expected pointer")
        || lower.contains("invalid mem access 'scalar'")
        || lower.contains("same insn cannot be used with different pointers")
    {
        return ProofObligation::PointerProvenance;
    }
    if lower.contains("too many states")
        || lower.contains("complexity")
        || lower.contains("loop is not bounded")
        || lower.contains("combined stack")
    {
        return ProofObligation::VerifierLimit;
    }
    if lower.contains("unknown func")
        || lower.contains("helper call is not allowed")
        || lower.contains("cannot use helper")
        || lower.contains("cannot call")
        || lower.contains("permission denied")
    {
        return ProofObligation::EnvironmentCapability;
    }
    if lower.contains("dynptr") {
        return ProofObligation::DynptrSafety;
    }
    ProofObligation::Unknown
}

fn parse_register_from_error(message: &str) -> Option<u8> {
    let bytes = message.as_bytes();
    let mut idx = 0usize;
    while idx + 1 < bytes.len() {
        if bytes[idx] != b'R' || !bytes[idx + 1].is_ascii_digit() {
            idx += 1;
            continue;
        }
        let start = idx + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        return message[start..end].parse().ok();
    }
    None
}

fn parse_i64_after(message: &str, needle: &str) -> Option<i64> {
    let start = message.find(needle)? + needle.len();
    let bytes = message.as_bytes();
    let mut end = start;
    if bytes.get(end) == Some(&b'-') {
        end += 1;
    }
    let digits_start = end;
    if message.get(end..end + 2) == Some("0x") {
        end += 2;
        while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
            end += 1;
        }
    } else {
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
    }
    if end == digits_start
        || (end == digits_start + 2 && message.get(digits_start..end) == Some("0x"))
    {
        return None;
    }
    let raw = &message[start..end];
    if let Some(hex) = raw.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(hex) = raw.strip_prefix("-0x") {
        i64::from_str_radix(hex, 16).ok().map(|value| -value)
    } else {
        raw.parse().ok()
    }
}

fn parse_helper_name(message: &str) -> Option<String> {
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

fn latest_reg_state(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    reg: u8,
) -> Option<&RegState> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .filter_map(|state| state.regs.get(&reg))
        .last()
}

fn latest_scalar_register(states: &[VerifierInsn], terminal_pc: Option<usize>) -> Option<u8> {
    states
        .iter()
        .filter(|state| terminal_pc.is_none_or(|pc| state.pc <= pc))
        .rev()
        .flat_map(|state| state.regs.iter())
        .find_map(|(&reg, state)| (state.reg_type == "scalar").then_some(reg))
}

pub(crate) fn scalar_range_summary(state: &RegState) -> String {
    if let Some(value) = state.exact_value {
        return format!("scalar exact {value}");
    }
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
    if parts.is_empty() {
        "scalar with unknown bounds".to_string()
    } else {
        format!("scalar({})", parts.join(","))
    }
}
