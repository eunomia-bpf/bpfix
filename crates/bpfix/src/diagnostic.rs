use anyhow::Result;
use bpfanalysis::{verifier_states_from_log, RegState, VerifierInsn};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierLogAnalysis {
    pub state_count: usize,
    pub required_proof: RequiredProof,
    pub events: Vec<ProofEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredProof {
    pub obligation: ProofObligation,
    pub register: Option<u8>,
    pub description: String,
    pub rejection_detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofObligation {
    PacketBounds,
    PointerProvenance,
    ScalarRange,
    NullablePointer,
    StackInitialized,
    ReferenceLifecycle,
    VerifierLimit,
    EnvironmentCapability,
    DynptrSafety,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofEventRole {
    ProofEstablished,
    ProofLost,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofEvent {
    pub role: ProofEventRole,
    pub obligation: ProofObligation,
    pub pc: Option<usize>,
    pub source: Option<SourceLocation>,
    pub register: Option<u8>,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLocation {
    pub path: String,
    pub line: usize,
    pub text: String,
}

#[derive(Clone, Debug)]
struct SourceEvent {
    pc: Option<usize>,
    source: SourceLocation,
}

pub fn analyze_verifier_log(
    log: &str,
    terminal_pc: Option<usize>,
    terminal_error: &str,
) -> Result<VerifierLogAnalysis> {
    let states = verifier_states_from_log(log)?;
    let source_events = collect_source_events(log);
    let required_proof = instantiate_required_proof(terminal_error, terminal_pc, &states);
    let obligation = required_proof.obligation;
    let register = required_proof.register;
    let rejected_source = terminal_source(&source_events, terminal_pc);
    let mut events = Vec::new();

    match obligation {
        ProofObligation::PointerProvenance => {
            events.extend(pointer_provenance_events(
                &states,
                &source_events,
                terminal_pc,
                rejected_source.as_ref(),
                register,
            ));
        }
        ProofObligation::PacketBounds => events.extend(packet_bounds_events(
            &source_events,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::ScalarRange => events.extend(scalar_range_events(
            &states,
            &source_events,
            terminal_pc,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::NullablePointer => events.extend(nullable_pointer_events(
            &states,
            &source_events,
            terminal_pc,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::StackInitialized => events.extend(stack_initialized_events(
            &source_events,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::ReferenceLifecycle => events.extend(reference_lifecycle_events(
            &source_events,
            rejected_source.as_ref(),
            register,
        )),
        ProofObligation::EnvironmentCapability => events.extend(environment_capability_events(
            &source_events,
            rejected_source.as_ref(),
            register,
        )),
        _ => {}
    }

    events.push(ProofEvent {
        role: ProofEventRole::Rejected,
        obligation,
        pc: terminal_pc,
        source: rejected_source,
        register,
        detail: required_proof.rejection_detail.clone(),
    });

    Ok(VerifierLogAnalysis {
        state_count: states.len(),
        required_proof,
        events,
    })
}

fn instantiate_required_proof(
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
            description: default_required_proof(obligation).to_string(),
            rejection_detail: rejected_detail(obligation).to_string(),
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
        _ => default_required_proof(ProofObligation::PacketBounds).to_string(),
    };
    let rejection_detail = match (register, required_end, proven_range) {
        (Some(reg), Some(required), Some(range)) => format!(
            "rejected here: verifier needs R{reg} packet range >= {required}, but only {range} bytes are proven"
        ),
        (Some(reg), Some(required), None) => format!(
            "rejected here: verifier needs R{reg} packet range >= {required} before this access"
        ),
        _ => rejected_detail(ProofObligation::PacketBounds).to_string(),
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
            _ => default_required_proof(ProofObligation::ScalarRange).to_string(),
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
        (None, _) => rejected_detail(ProofObligation::ScalarRange).to_string(),
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
        None => default_required_proof(ProofObligation::NullablePointer).to_string(),
    };
    let rejection_detail = match register {
        Some(reg) if message.contains("pointer arithmetic") => {
            format!("rejected here: R{reg} is still nullable, so pointer arithmetic is prohibited")
        }
        Some(reg) => format!("rejected here: R{reg} is still nullable at the use site"),
        None => rejected_detail(ProofObligation::NullablePointer).to_string(),
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
        None => default_required_proof(ProofObligation::StackInitialized).to_string(),
    };
    let rejection_detail = match register {
        Some(reg) if message.contains("!read_ok") => {
            format!("rejected here: R{reg} is not readable on this path")
        }
        Some(reg) => {
            format!("rejected here: stack memory reachable from R{reg} is not fully initialized")
        }
        None => rejected_detail(ProofObligation::StackInitialized).to_string(),
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
        None => default_required_proof(ProofObligation::ReferenceLifecycle).to_string(),
    };
    let rejection_detail = match ref_id {
        Some(id) => format!("rejected here: reference id {id} is not released on every path"),
        None => rejected_detail(ProofObligation::ReferenceLifecycle).to_string(),
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
        None => default_required_proof(ProofObligation::EnvironmentCapability).to_string(),
    };
    let rejection_detail = match helper {
        Some(helper) => format!("rejected here: this program type cannot use {helper}"),
        None => rejected_detail(ProofObligation::EnvironmentCapability).to_string(),
    };
    RequiredProof {
        obligation: ProofObligation::EnvironmentCapability,
        register: parse_register_from_error(message),
        description,
        rejection_detail,
    }
}

fn pointer_provenance_events(
    states: &[VerifierInsn],
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(source) = rejected_source {
        if let Some(event) = latest_source_before(source_events, Some(source), |text| {
            text.contains("if (") && !text.contains("data_end")
        }) {
            events.push(ProofEvent {
                role: ProofEventRole::ProofLost,
                obligation: ProofObligation::PointerProvenance,
                pc: event.pc,
                source: Some(event.source.clone()),
                register,
                detail: "proof can be lost when branch-specific pointers are merged".to_string(),
            });
        }

        if let Some(event) = latest_source_before(source_events, Some(source), |text| {
            text.contains("data_end")
        }) {
            events.push(ProofEvent {
                role: ProofEventRole::ProofEstablished,
                obligation: ProofObligation::PointerProvenance,
                pc: event.pc,
                source: Some(event.source.clone()),
                register,
                detail: "proof established by a verifier-visible bounds check".to_string(),
            });
        }
    }

    if events
        .iter()
        .any(|event| event.role == ProofEventRole::ProofLost)
    {
        return events;
    }

    if let Some((pc, kind)) = latest_pointer_to_scalar_transition(states, terminal_pc, register) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            obligation: ProofObligation::PointerProvenance,
            pc: Some(pc),
            source: source_for_pc(source_events, pc).cloned(),
            register,
            detail: format!(
                "verifier state changes from {kind} to scalar before the rejected access"
            ),
        });
    }

    events
}

fn latest_pointer_to_scalar_transition(
    states: &[VerifierInsn],
    terminal_pc: Option<usize>,
    register: Option<u8>,
) -> Option<(usize, String)> {
    let reg = register?;
    let mut latest_pointer: Option<(usize, String)> = None;
    let mut latest_loss = None;
    for state in states {
        if terminal_pc.is_some_and(|pc| state.pc > pc) {
            continue;
        }
        let Some(reg_state) = state.regs.get(&reg) else {
            continue;
        };
        if is_pointer_state(reg_state) {
            latest_pointer = Some((state.pc, reg_state.reg_type.clone()));
        } else if reg_state.reg_type == "scalar" {
            if let Some((_, pointer_kind)) = latest_pointer.as_ref() {
                latest_loss = Some((state.pc, pointer_kind.clone()));
            }
        }
    }
    latest_loss
}

fn is_pointer_state(state: &RegState) -> bool {
    state.reg_type != "scalar" && state.reg_type != "fp"
}

fn packet_bounds_events(
    source_events: &[SourceEvent],
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_packet_bounds_check(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            obligation: ProofObligation::PacketBounds,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "packet bounds proof is established by this data_end check".to_string(),
        });
    }
    events
}

fn scalar_range_events(
    states: &[VerifierInsn],
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_scalar_guard(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            obligation: ProofObligation::ScalarRange,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "scalar range guard is visible before the rejected operation".to_string(),
        });
    }

    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        text.contains("volatile") || text.contains("asm volatile")
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            obligation: ProofObligation::ScalarRange,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "bounded scalar proof can be lost when the checked value is materialized as a different verifier value"
                .to_string(),
        });
        return events;
    }

    let Some(reg) = register else {
        return events;
    };
    if let Some((pc, state)) = latest_unsafe_scalar_state(states, terminal_pc, reg) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            obligation: ProofObligation::ScalarRange,
            pc: Some(pc),
            source: source_for_pc(source_events, pc).cloned(),
            register,
            detail: format!(
                "verifier still sees R{reg} as {}, so the required scalar bound is not available at the use",
                scalar_range_summary(state)
            ),
        });
    }
    events
}

fn nullable_pointer_events(
    states: &[VerifierInsn],
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_null_check(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            obligation: ProofObligation::NullablePointer,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "non-null proof is established in this branch".to_string(),
        });
    }

    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_nullable_return(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            obligation: ProofObligation::NullablePointer,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "nullable pointer returned here reaches the use without a verifier-visible non-null proof"
                .to_string(),
        });
        return events;
    }

    let Some(reg) = register else {
        return events;
    };
    if let Some((pc, kind)) = latest_nullable_state(states, terminal_pc, reg) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            obligation: ProofObligation::NullablePointer,
            pc: Some(pc),
            source: source_for_pc(source_events, pc).cloned(),
            register,
            detail: format!("verifier still tracks R{reg} as nullable type {kind}"),
        });
    }
    events
}

fn stack_initialized_events(
    source_events: &[SourceEvent],
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_stack_initialization(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            obligation: ProofObligation::StackInitialized,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "some stack/register initialization is visible before the rejected use"
                .to_string(),
        });
    }
    events
}

fn reference_lifecycle_events(
    source_events: &[SourceEvent],
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_reference_acquire(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            obligation: ProofObligation::ReferenceLifecycle,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "verifier-tracked reference is acquired here".to_string(),
        });
    }
    if let Some(event) = latest_source_before(source_events, rejected_source, |text| {
        looks_like_reference_release(text)
    }) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofEstablished,
            obligation: ProofObligation::ReferenceLifecycle,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "reference release is visible on one path".to_string(),
        });
    }
    if let Some(source) = rejected_source {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            obligation: ProofObligation::ReferenceLifecycle,
            pc: None,
            source: Some(source.clone()),
            register,
            detail: "release proof must hold on every exit path, not only the path shown above"
                .to_string(),
        });
    }
    events
}

fn environment_capability_events(
    source_events: &[SourceEvent],
    rejected_source: Option<&SourceLocation>,
    register: Option<u8>,
) -> Vec<ProofEvent> {
    let mut events = Vec::new();
    if let Some(source) = rejected_source.filter(|source| source.text.contains("bpf_")) {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            obligation: ProofObligation::EnvironmentCapability,
            pc: None,
            source: Some(source.clone()),
            register,
            detail: "this helper call requires a program type, attach type, or kernel capability not available to the load"
                .to_string(),
        });
        return events;
    }
    if let Some(event) =
        latest_source_before(source_events, rejected_source, |text| text.contains("bpf_"))
    {
        events.push(ProofEvent {
            role: ProofEventRole::ProofLost,
            obligation: ProofObligation::EnvironmentCapability,
            pc: event.pc,
            source: Some(event.source.clone()),
            register,
            detail: "this helper call requires a program type, attach type, or kernel capability not available to the load"
                .to_string(),
        });
    }
    events
}

pub fn infer_obligation(message: &str) -> ProofObligation {
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

fn rejected_detail(obligation: ProofObligation) -> &'static str {
    match obligation {
        ProofObligation::PacketBounds => {
            "rejected here: packet access is not proven to stay before data_end"
        }
        ProofObligation::PointerProvenance => {
            "rejected here: verifier sees a scalar where a pointer is required"
        }
        ProofObligation::ScalarRange => {
            "rejected here: scalar range is not proven safe for this memory operation"
        }
        ProofObligation::NullablePointer => {
            "rejected here: nullable pointer is used without a visible non-null proof"
        }
        ProofObligation::StackInitialized => {
            "rejected here: stack bytes are not proven initialized"
        }
        ProofObligation::ReferenceLifecycle => {
            "rejected here: reference is not proven released on all paths"
        }
        ProofObligation::VerifierLimit => {
            "rejected here: verifier analysis budget or loop proof is exhausted"
        }
        ProofObligation::EnvironmentCapability => {
            "rejected here: kernel or program type does not expose this capability"
        }
        ProofObligation::DynptrSafety => {
            "rejected here: dynptr lifetime or bounds proof is missing"
        }
        ProofObligation::Unknown => "rejected here: required verifier proof is missing",
    }
}

fn default_required_proof(obligation: ProofObligation) -> &'static str {
    match obligation {
        ProofObligation::PacketBounds => {
            "prove that the packet pointer plus requested access size stays before data_end on every path reaching the load, store, or helper call"
        }
        ProofObligation::PointerProvenance => {
            "preserve a verifier-recognized pointer type at the operation that requires a pointer"
        }
        ProofObligation::ScalarRange => {
            "bound the scalar value tightly enough for the verifier to prove the memory access range"
        }
        ProofObligation::NullablePointer => {
            "prove that the nullable pointer returned by a helper is checked for null before dereference or helper reuse"
        }
        ProofObligation::StackInitialized => {
            "initialize every stack byte that can be read directly or passed indirectly to a helper"
        }
        ProofObligation::ReferenceLifecycle => {
            "release every acquired verifier-tracked reference on every exit path"
        }
        ProofObligation::VerifierLimit => {
            "reduce verifier state growth or provide a statically bounded loop shape"
        }
        ProofObligation::EnvironmentCapability => {
            "load the program with a kernel, program type, attach point, and privileges that support the requested helper or kfunc"
        }
        ProofObligation::DynptrSafety => {
            "keep dynptr slices inside their proven lifetime, initialized range, and read/write mode"
        }
        ProofObligation::Unknown => {
            "inspect the terminal verifier line and add the missing safety proof required at that program point"
        }
    }
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

fn latest_unsafe_scalar_state(
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
            (reg_state.reg_type == "scalar" && scalar_range_is_unsafe(reg_state))
                .then_some((state.pc, reg_state))
        })
}

fn latest_nullable_state(
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

fn scalar_range_is_unsafe(state: &RegState) -> bool {
    state.range.smin.is_none_or(|value| value < 0)
        || state.range.umin.is_none()
        || state.range.umax.is_none_or(|value| value > i32::MAX as u64)
}

fn scalar_range_summary(state: &RegState) -> String {
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

fn collect_source_events(log: &str) -> Vec<SourceEvent> {
    let lines = log.lines().collect::<Vec<_>>();
    let mut events = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(source) = parse_source_comment(line) else {
            continue;
        };
        let pc = lines
            .iter()
            .skip(idx + 1)
            .take(4)
            .find_map(|next| parse_instruction_pc(next));
        events.push(SourceEvent { pc, source });
    }
    events
}

fn parse_source_comment(line: &str) -> Option<SourceLocation> {
    let (source, tail) = line.rsplit_once(" @ ")?;
    let (path, line_no) = tail.trim().rsplit_once(':')?;
    Some(SourceLocation {
        path: path.to_string(),
        line: line_no.parse().ok()?,
        text: source.trim().trim_start_matches(';').trim().to_string(),
    })
}

fn parse_instruction_pc(line: &str) -> Option<usize> {
    let trimmed = line.trim_start();
    let digits_len = trimmed
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits_len == 0 || trimmed.as_bytes().get(digits_len) != Some(&b':') {
        return None;
    }
    trimmed[..digits_len].parse().ok()
}

fn terminal_source(
    source_events: &[SourceEvent],
    terminal_pc: Option<usize>,
) -> Option<SourceLocation> {
    match terminal_pc {
        Some(pc) => source_for_pc(source_events, pc).cloned(),
        None => source_events.last().map(|event| event.source.clone()),
    }
}

fn source_for_pc(source_events: &[SourceEvent], pc: usize) -> Option<&SourceLocation> {
    source_events
        .iter()
        .filter(|event| event.pc.is_some_and(|event_pc| event_pc <= pc))
        .max_by_key(|event| event.pc)
        .map(|event| &event.source)
}

fn latest_source_before<'a>(
    source_events: &'a [SourceEvent],
    rejected_source: Option<&SourceLocation>,
    predicate: impl Fn(&str) -> bool,
) -> Option<&'a SourceEvent> {
    let rejected_source = rejected_source?;
    source_events
        .iter()
        .filter(|event| event.source.path == rejected_source.path)
        .filter(|event| event.source.line < rejected_source.line)
        .filter(|event| predicate(&event.source.text))
        .max_by_key(|event| event.source.line)
}

fn looks_like_scalar_guard(text: &str) -> bool {
    text.starts_with("if ")
        && (text.contains('<')
            || text.contains('>')
            || text.contains("<=")
            || text.contains(">=")
            || text.contains("!=")
            || text.contains("=="))
}

fn looks_like_packet_bounds_check(text: &str) -> bool {
    text.starts_with("if ") && text.contains("data_end")
}

fn looks_like_null_check(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.starts_with("if ")
        && (lower.contains("null")
            || lower.contains("!tmp")
            || lower.contains("!val")
            || lower.contains("!ptr")
            || lower.contains("!value")
            || lower.contains("== 0")
            || lower.contains("!= 0")
            || lower.contains("== null")
            || lower.contains("!= null"))
}

fn looks_like_nullable_return(text: &str) -> bool {
    text.contains("bpf_map_lookup_elem")
        || text.contains("bpf_ringbuf_reserve")
        || text.contains("bpf_sk_lookup")
        || text.contains("bpf_skc_lookup")
}

fn looks_like_stack_initialization(text: &str) -> bool {
    text.contains('=') && (text.contains("0") || text.contains("memset"))
}

fn looks_like_reference_acquire(text: &str) -> bool {
    text.contains("bpf_ringbuf_reserve")
        || text.contains("bpf_sk_lookup")
        || text.contains("bpf_skc_lookup")
}

fn looks_like_reference_release(text: &str) -> bool {
    text.contains("bpf_ringbuf_discard")
        || text.contains("bpf_ringbuf_submit")
        || text.contains("bpf_sk_release")
}

#[cfg(test)]
mod tests {
    use super::{analyze_verifier_log, ProofEventRole, ProofObligation};

    #[test]
    fn branch_merge_case_produces_proof_lifecycle_events() {
        let log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
        let analysis =
            analyze_verifier_log(log, Some(37), "R5 invalid mem access 'scalar'").unwrap();

        assert_eq!(analysis.state_count, 60);
        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::PointerProvenance
        );
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 263
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofEstablished
                && event.source.as_ref().unwrap().line == 267
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 270
        }));
    }

    #[test]
    fn scalar_range_case_identifies_obligation_and_rejection() {
        let log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(33),
            "value -2147483648 makes pkt pointer be out of bounds",
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::ScalarRange
        );
        assert!(analysis
            .required_proof
            .description
            .contains("cannot be negative"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 274
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 280
        }));
    }

    #[test]
    fn packet_bounds_case_instantiates_required_range() {
        let log =
            include_str!("../../../bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(26),
            "invalid access to packet, off=34 size=64, R3(id=0,off=34,r=42)",
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::PacketBounds
        );
        assert!(analysis.required_proof.description.contains("R3"));
        assert!(analysis.required_proof.description.contains("98"));
        assert!(analysis.required_proof.description.contains("42"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofEstablished
                && event.source.as_ref().unwrap().line == 52
        }));
    }

    #[test]
    fn nullable_pointer_case_points_at_unchecked_helper_result() {
        let log =
            include_str!("../../../bpfix-bench/cases/github-iovisor-bcc-10/replay-verifier.log");
        let analysis =
            analyze_verifier_log(log, Some(7), "R0 invalid mem access 'map_value_or_null'")
                .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::NullablePointer
        );
        assert!(analysis.required_proof.description.contains("R0"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 24
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 25
        }));
    }

    #[test]
    fn environment_case_instantiates_helper_contract() {
        let log =
            include_str!("../../../bpfix-bench/cases/github-aya-rs-aya-1233/replay-verifier.log");
        let analysis = analyze_verifier_log(
            log,
            Some(8),
            "program of this type cannot use helper bpf_probe_read#4",
        )
        .unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::EnvironmentCapability
        );
        assert!(analysis
            .required_proof
            .description
            .contains("bpf_probe_read#4"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 13
        }));
    }

    #[test]
    fn stack_readability_case_instantiates_register_requirement() {
        let analysis =
            analyze_verifier_log("0: (95) exit\nR0 !read_ok\n", Some(0), "R0 !read_ok").unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::StackInitialized
        );
        assert!(analysis.required_proof.description.contains("R0"));
        assert!(analysis
            .required_proof
            .rejection_detail
            .contains("not readable"));
    }

    #[test]
    fn reference_lifecycle_case_reports_acquire_and_exit() {
        let log = "\
; ref = bpf_ringbuf_reserve(&rb, 8, 0); @ prog.c:10
5: (85) call bpf_ringbuf_reserve#131 ; R0_w=ringbuf_mem_or_null(id=2,ref_obj_id=2) refs=2
; return 0; @ prog.c:11
6: (95) exit
Unreleased reference id=2 alloc_insn=5
";
        let analysis =
            analyze_verifier_log(log, Some(6), "Unreleased reference id=2 alloc_insn=5").unwrap();

        assert_eq!(
            analysis.required_proof.obligation,
            ProofObligation::ReferenceLifecycle
        );
        assert!(analysis
            .required_proof
            .description
            .contains("reference id 2"));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofEstablished
                && event.source.as_ref().unwrap().line == 10
        }));
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 11
        }));
    }
}
