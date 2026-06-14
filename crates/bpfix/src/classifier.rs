use crate::family::ProofObligation;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Classification {
    pub(crate) error_id: &'static str,
    pub(crate) obligation: ProofObligation,
    pub(crate) failure_class: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) required_proof: &'static str,
    pub(crate) help: &'static [&'static str],
    pub(crate) confidence: &'static str,
    pub(crate) diagnostic_kind: &'static str,
    pub(crate) help_safety: &'static str,
}

impl Classification {
    const fn supported(
        error_id: &'static str,
        obligation: ProofObligation,
        failure_class: &'static str,
        summary: &'static str,
        help: &'static [&'static str],
    ) -> Self {
        Self {
            error_id,
            obligation,
            failure_class,
            summary,
            required_proof: obligation.default_required_proof(),
            help,
            confidence: "medium",
            diagnostic_kind: "supported",
            help_safety: "repair_hint",
        }
    }

    const fn triage(
        error_id: &'static str,
        obligation: ProofObligation,
        failure_class: &'static str,
        summary: &'static str,
        help: &'static [&'static str],
    ) -> Self {
        Self {
            error_id,
            obligation,
            failure_class,
            summary,
            required_proof: obligation.default_required_proof(),
            help,
            confidence: "medium",
            diagnostic_kind: "supported",
            help_safety: "triage_only",
        }
    }

    const fn custom_triage(
        error_id: &'static str,
        failure_class: &'static str,
        summary: &'static str,
        required_proof: &'static str,
        help: &'static [&'static str],
        diagnostic_kind: &'static str,
        confidence: &'static str,
    ) -> Self {
        Self {
            error_id,
            obligation: ProofObligation::Unknown,
            failure_class,
            summary,
            required_proof,
            help,
            confidence,
            diagnostic_kind,
            help_safety: "triage_only",
        }
    }
}

pub(crate) fn no_verifier_rejection_classification() -> Classification {
    Classification::custom_triage(
        "BPFIX-E000",
        "input_error",
        "no verifier rejection was found",
        "provide a full verifier/build/load log that contains the verifier rejection region",
        &[
            "Re-run the failing load with bpftool -d or enable libbpf verifier logging.",
            "Pass the full stderr from the failing load command, not only the final loader error.",
        ],
        "unsupported_input",
        "low",
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifierRejectionKind {
    PacketBounds,
    NullablePointer,
    StackInitialized,
    ReferenceLifecycle,
    Alignment,
    HelperArgument,
    StructAccess,
    ContextUnavailable,
    TypeContract,
    InstructionSupport,
    EnvironmentCapability,
    DynptrSafety,
    KfuncReference,
    IteratorLifecycle,
    LockState,
    ScalarRange,
    PointerProvenance,
    LoopBound,
    VerifierLimit,
}

#[derive(Clone, Copy)]
struct RejectionPattern {
    kind: VerifierRejectionKind,
    any: &'static [&'static str],
    all: &'static [&'static str],
}

impl RejectionPattern {
    const fn any(kind: VerifierRejectionKind, any: &'static [&'static str]) -> Self {
        Self {
            kind,
            any,
            all: &[],
        }
    }

    const fn all(kind: VerifierRejectionKind, all: &'static [&'static str]) -> Self {
        Self {
            kind,
            any: &[],
            all,
        }
    }

    fn matches(self, message: &str) -> bool {
        (self.any.is_empty() || self.any.iter().any(|needle| message.contains(needle)))
            && self.all.iter().all(|needle| message.contains(needle))
    }
}

const REJECTION_PATTERNS: &[RejectionPattern] = &[
    RejectionPattern::any(
        VerifierRejectionKind::PacketBounds,
        &["invalid access to packet", "outside of the packet"],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::NullablePointer,
        &[
            "map_value_or_null",
            "ptr_or_null",
            "mem_or_null",
            "possibly null",
        ],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::StackInitialized,
        &[
            "invalid read from stack",
            "invalid indirect read from stack",
            "invalid write to stack",
            "uninitialized",
            "!read_ok",
        ],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::ReferenceLifecycle,
        &["unreleased reference", "reference has not been released"],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::Alignment,
        &["misaligned", "not aligned"],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::HelperArgument,
        &[
            "caller passes invalid args",
            "invalid args",
            "invalid argument",
            "bad argument",
            "arg#",
            "helper access to the packet is not allowed",
            "cannot call exception cb directly",
            "only read from",
        ],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::StructAccess,
        &["access beyond struct"],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::ContextUnavailable,
        &[
            "invalid bpf_context access",
            "invalid ctx access",
            "invalid access to context",
        ],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::TypeContract,
        &["unsupported reg type"],
    ),
    RejectionPattern::all(VerifierRejectionKind::TypeContract, &["type=", "expected="]),
    RejectionPattern::any(
        VerifierRejectionKind::TypeContract,
        &[
            "expected pointer",
            "expected=fp",
            "expected=pkt",
            "expected=map_ptr",
            "expected=map_value",
        ],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::InstructionSupport,
        &["jit does not support", "unsupported", "unknown opcode"],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::EnvironmentCapability,
        &["calling kernel function"],
    ),
    RejectionPattern::any(VerifierRejectionKind::DynptrSafety, &["dynptr"]),
    RejectionPattern::any(
        VerifierRejectionKind::KfuncReference,
        &[
            "kfunc",
            "trusted",
            "ref_obj_id",
            "acquire",
            "has no valid kptr",
        ],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::IteratorLifecycle,
        &["iter", "iterator"],
    ),
    RejectionPattern::any(VerifierRejectionKind::LockState, &["irq", "rcu", "lock"]),
    RejectionPattern::any(
        VerifierRejectionKind::ScalarRange,
        &[
            "unbounded",
            "min value is negative",
            "min value is outside",
            "out of bounds",
            "invalid access to map value",
            "invalid zero-sized",
            "makes pkt pointer",
            "outside of allowed memory range",
            "outside of the allowed memory range",
            "invalid variable-offset",
            "invalid access to memory",
        ],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::PointerProvenance,
        &[
            "invalid mem access 'scalar'",
            "same insn cannot be used with different pointers",
            "pointer arithmetic",
            "dereference of modified ctx ptr",
        ],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::LoopBound,
        &["loop is not bounded", "infinite loop detected", "back-edge"],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::VerifierLimit,
        &[
            "too many states",
            "bpf program is too large",
            "combined stack size",
            "complexity",
            "combined stack",
            "processed 1000001 insn",
        ],
    ),
    RejectionPattern::any(
        VerifierRejectionKind::EnvironmentCapability,
        &[
            "unknown func",
            "helper call is not allowed",
            "program of this type cannot use helper",
            "cannot use helper",
            "missing btf",
            "cannot call",
            "permission denied",
        ],
    ),
];

impl VerifierRejectionKind {
    fn parse(message: &str) -> Option<Self> {
        REJECTION_PATTERNS
            .iter()
            .find(|pattern| pattern.matches(message))
            .map(|pattern| pattern.kind)
    }

    const fn classification(self) -> Classification {
        match self {
            Self::PacketBounds => Classification::supported(
                "BPFIX-E001",
                ProofObligation::PacketBounds,
                "source_bug",
                "packet bounds proof is missing",
                &[
                    "Add or move a packet bounds check immediately before the access or helper argument use.",
                    "Check the exact pointer and byte length passed to the helper, not only an earlier header pointer.",
                ],
            ),
            Self::NullablePointer => Classification::supported(
                "BPFIX-E002",
                ProofObligation::NullablePointer,
                "source_bug",
                "nullable pointer proof is missing",
                &[
                    "Add an explicit null check and keep the dereference inside the non-null branch.",
                    "Avoid copying the nullable value through a path that loses the verifier's refined type.",
                ],
            ),
            Self::StackInitialized => Classification::supported(
                "BPFIX-E003",
                ProofObligation::StackInitialized,
                "source_bug",
                "stack initialization proof is missing",
                &[
                    "Initialize the full stack object before the helper call or load.",
                    "Reduce the helper length argument so it covers only initialized bytes.",
                ],
            ),
            Self::ReferenceLifecycle => Classification::supported(
                "BPFIX-E004",
                ProofObligation::ReferenceLifecycle,
                "source_bug",
                "reference lifecycle proof is missing",
                &[
                    "Call the matching release helper before each return.",
                    "Restructure error paths so acquired references share one cleanup block.",
                ],
            ),
            Self::Alignment => Classification::supported(
                "BPFIX-E007",
                ProofObligation::Alignment,
                "source_bug",
                "memory alignment proof is missing",
                &[
                    "Align the object or access it with a smaller load/store size that matches the verifier-proven alignment.",
                    "Avoid pointer arithmetic that hides the final aligned offset from the verifier.",
                ],
            ),
            Self::HelperArgument => Classification::supported(
                "BPFIX-E010",
                ProofObligation::HelperArgument,
                "source_bug",
                "helper or subprogram argument contract is not satisfied",
                &[
                    "Check the exact register passed as each helper or subprogram argument.",
                    "Keep argument range, nullability, and pointer type refinements visible at the call site.",
                ],
            ),
            Self::StructAccess => Classification::supported(
                "BPFIX-E011",
                ProofObligation::ContextAccess,
                "source_bug",
                "context or kernel-struct field access is invalid",
                &[
                    "Check the BTF type, program context type, and field offset used by the access.",
                    "Use CO-RE field access helpers or a program type whose context exposes the requested field.",
                ],
            ),
            Self::ContextUnavailable => Classification::triage(
                "BPFIX-E011",
                ProofObligation::ContextAccess,
                "environment_or_configuration",
                "program context field is unavailable",
                &[
                    "Check the section name, program type, and attach type used by the loader.",
                    "Use only context fields documented for this program type, or move the logic to a compatible hook.",
                ],
            ),
            Self::TypeContract => Classification::supported(
                "BPFIX-E008",
                ProofObligation::TypeContract,
                "source_bug",
                "verifier-visible type does not match the required type",
                &[
                    "Avoid casts, arithmetic, or spills that convert the required pointer-like value into a scalar.",
                    "Pass the verifier-tracked value directly, or rederive it from a checked base immediately before use.",
                ],
            ),
            Self::InstructionSupport => Classification::triage(
                "BPFIX-E016",
                ProofObligation::InstructionSupport,
                "environment_or_configuration",
                "kernel, JIT, or instruction-set support is unavailable",
                &[
                    "Check the target kernel version, JIT support, and compiler flags used for this object.",
                    "Regenerate the BPF object for a supported instruction set or disable the unsupported feature path.",
                ],
            ),
            Self::EnvironmentCapability => Classification::triage(
                "BPFIX-E009",
                ProofObligation::EnvironmentCapability,
                "environment_or_configuration",
                "kernel or program-type capability is unavailable",
                &[
                    "Check kernel version, program type, attach type, capabilities, and BTF availability.",
                    "Use a supported helper or gate the code path by target kernel capabilities.",
                ],
            ),
            Self::DynptrSafety => Classification::supported(
                "BPFIX-E012",
                ProofObligation::DynptrSafety,
                "source_bug",
                "dynptr lifetime or bounds proof is missing",
                &[
                    "Revalidate dynptr slice nullability and length before use.",
                    "Do not reuse a dynptr slice after an operation that invalidates it.",
                ],
            ),
            Self::KfuncReference => Classification::supported(
                "BPFIX-E013",
                ProofObligation::KfuncReference,
                "source_bug",
                "kfunc trusted-pointer or reference contract is not satisfied",
                &[
                    "Check whether the kfunc requires a trusted, non-null, or referenced pointer.",
                    "Release acquired references on every exit path and avoid reusing invalidated references.",
                ],
            ),
            Self::IteratorLifecycle => Classification::supported(
                "BPFIX-E014",
                ProofObligation::IteratorLifecycle,
                "source_bug",
                "iterator lifecycle proof is missing",
                &[
                    "Destroy iterator state on all exit paths.",
                    "Do not read iterator-owned state after the verifier-visible destroy or invalidation point.",
                ],
            ),
            Self::LockState => Classification::supported(
                "BPFIX-E015",
                ProofObligation::LockState,
                "source_bug",
                "lock, RCU, or IRQ state discipline is violated",
                &[
                    "Keep acquire and release operations balanced on every path.",
                    "Avoid restoring IRQ or lock state out of order across branches and callbacks.",
                ],
            ),
            Self::ScalarRange => Classification::supported(
                "BPFIX-E005",
                ProofObligation::ScalarRange,
                "source_bug",
                "scalar range proof is missing",
                &[
                    "Clamp the index or length with explicit upper and lower bounds.",
                    "Keep the bounded scalar in the same SSA value used for pointer arithmetic or helper length.",
                ],
            ),
            Self::PointerProvenance => Classification::supported(
                "BPFIX-E006",
                ProofObligation::PointerProvenance,
                "source_bug",
                "pointer type proof is missing",
                &[
                    "Avoid integer casts or arithmetic that turn the pointer into a scalar before the access.",
                    "Recompute the pointer from a verifier-tracked base after scalar manipulation.",
                ],
            ),
            Self::LoopBound => Classification::supported(
                "BPFIX-E018",
                ProofObligation::LoopBound,
                "source_bug",
                "loop bound proof is missing",
                &[
                    "Add a constant upper bound or clamp the loop induction variable before the loop.",
                    "Avoid data-dependent back edges that the verifier cannot prove will terminate.",
                ],
            ),
            Self::VerifierLimit => Classification::supported(
                "BPFIX-E018",
                ProofObligation::VerifierLimit,
                "verifier_limit",
                "verifier resource limit was reached",
                &[
                    "Add a constant loop bound or split complex control flow into smaller helper programs.",
                    "For combined stack-size errors, reduce stack usage across caller, subprogram, and callback frames.",
                    "Reduce path-sensitive state by simplifying branches and stack state carried through the loop.",
                ],
            ),
        }
    }
}

pub(crate) fn classify(message: &str) -> Classification {
    let lower = message.to_ascii_lowercase();
    VerifierRejectionKind::parse(&lower)
        .map(VerifierRejectionKind::classification)
        .unwrap_or_else(unsupported_message_classification)
}

fn unsupported_message_classification() -> Classification {
    Classification::custom_triage(
        "BPFIX-E099",
        "unsupported_verifier_message",
        "verifier rejection needs manual triage",
        "inspect the terminal verifier message and collect a full verifier log for this unsupported message shape",
        &[
            "Pass the full verifier log with instruction states and source annotations if available.",
            "File an issue with the terminal verifier message so BPFix can add a safe diagnostic family.",
        ],
        "unsupported_verifier_message",
        "low",
    )
}

#[cfg(test)]
mod tests {
    use super::{classify, VerifierRejectionKind};

    #[test]
    fn parses_rejection_kind_before_mapping_to_diagnostic_class() {
        assert_eq!(
            VerifierRejectionKind::parse("r5 invalid mem access 'scalar'"),
            Some(VerifierRejectionKind::PointerProvenance)
        );
        assert_eq!(
            VerifierRejectionKind::parse("invalid access to packet, off=42 size=4, r=40"),
            Some(VerifierRejectionKind::PacketBounds)
        );
        assert_eq!(
            VerifierRejectionKind::parse(
                "program of this type cannot use helper bpf_xdp_adjust_head"
            ),
            Some(VerifierRejectionKind::EnvironmentCapability)
        );
    }

    #[test]
    fn unsupported_messages_remain_explicit_triage() {
        let class = classify("a new verifier rejection shape");
        assert_eq!(class.error_id, "BPFIX-E099");
        assert_eq!(class.failure_class, "unsupported_verifier_message");
    }
}
