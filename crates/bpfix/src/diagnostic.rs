use anyhow::Result;
use bpfanalysis::{verifier_states_from_log, RegState, VerifierInsn};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierLogAnalysis {
    pub state_count: usize,
    pub obligation: ProofObligation,
    pub events: Vec<ProofEvent>,
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
    let obligation = infer_obligation(terminal_error);
    let register = parse_register_from_error(terminal_error);
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
        ProofObligation::PacketBounds => {
            if let Some(event) =
                latest_source_before(&source_events, rejected_source.as_ref(), |text| {
                    text.contains("data_end")
                })
            {
                events.push(ProofEvent {
                    role: ProofEventRole::ProofEstablished,
                    obligation,
                    pc: event.pc,
                    source: Some(event.source.clone()),
                    register,
                    detail: "packet bounds proof is visible before the rejected access".to_string(),
                });
            }
        }
        ProofObligation::ScalarRange => {
            if let Some(event) =
                latest_source_before(&source_events, rejected_source.as_ref(), |text| {
                    looks_like_scalar_guard(text)
                })
            {
                events.push(ProofEvent {
                    role: ProofEventRole::ProofEstablished,
                    obligation,
                    pc: event.pc,
                    source: Some(event.source.clone()),
                    register,
                    detail: "scalar range guard is visible before the rejected operation"
                        .to_string(),
                });
            }
        }
        _ => {}
    }

    events.push(ProofEvent {
        role: ProofEventRole::Rejected,
        obligation,
        pc: terminal_pc,
        source: rejected_source,
        register,
        detail: rejected_detail(obligation).to_string(),
    });

    Ok(VerifierLogAnalysis {
        state_count: states.len(),
        obligation,
        events,
    })
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

pub fn infer_obligation(message: &str) -> ProofObligation {
    let lower = message.to_ascii_lowercase();
    if lower.contains("invalid access to packet") || lower.contains("outside of the packet") {
        return ProofObligation::PacketBounds;
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
        assert_eq!(analysis.obligation, ProofObligation::PointerProvenance);
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

        assert_eq!(analysis.obligation, ProofObligation::ScalarRange);
        assert!(analysis.events.iter().any(|event| {
            event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 280
        }));
    }
}
