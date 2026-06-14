use crate::family::ProofObligation;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Classification {
    pub(crate) error_id: &'static str,
    pub(crate) failure_class: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) required_proof: &'static str,
    pub(crate) help: &'static [&'static str],
    pub(crate) confidence: &'static str,
    pub(crate) diagnostic_kind: &'static str,
    pub(crate) help_safety: &'static str,
}

pub(crate) fn no_verifier_rejection_classification() -> Classification {
    triage_class(
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

fn triage_class(
    error_id: &'static str,
    failure_class: &'static str,
    summary: &'static str,
    required_proof: &'static str,
    help: &'static [&'static str],
    diagnostic_kind: &'static str,
    confidence: &'static str,
) -> Classification {
    Classification {
        error_id,
        failure_class,
        summary,
        required_proof,
        help,
        confidence,
        diagnostic_kind,
        help_safety: "triage_only",
    }
}

struct ClassRule {
    any: &'static [&'static str],
    all: &'static [&'static str],
    class: Classification,
}

impl ClassRule {
    fn matches(&self, message: &str) -> bool {
        (self.any.is_empty() || self.any.iter().any(|pattern| message.contains(pattern)))
            && self.all.iter().all(|pattern| message.contains(pattern))
    }
}

macro_rules! supported_rule {
    ($any:expr, $obligation:expr, $error_id:literal, $failure_class:literal, $summary:literal, $help:expr) => {
        ClassRule {
            any: $any,
            all: &[],
            class: Classification {
                error_id: $error_id,
                failure_class: $failure_class,
                summary: $summary,
                required_proof: ($obligation).default_required_proof(),
                help: $help,
                confidence: "medium",
                diagnostic_kind: "supported",
                help_safety: "repair_hint",
            },
        }
    };
}

macro_rules! triage_rule {
    ($any:expr, $obligation:expr, $error_id:literal, $failure_class:literal, $summary:literal, $help:expr) => {
        ClassRule {
            any: $any,
            all: &[],
            class: Classification {
                error_id: $error_id,
                failure_class: $failure_class,
                summary: $summary,
                required_proof: ($obligation).default_required_proof(),
                help: $help,
                confidence: "medium",
                diagnostic_kind: "supported",
                help_safety: "triage_only",
            },
        }
    };
}

const CLASS_RULES: &[ClassRule] = &[
    supported_rule!(
        &["invalid access to packet", "outside of the packet"],
        ProofObligation::PacketBounds,
        "BPFIX-E001",
        "source_bug",
        "packet bounds proof is missing",
        &[
            "Add or move a packet bounds check immediately before the access or helper argument use.",
            "Check the exact pointer and byte length passed to the helper, not only an earlier header pointer.",
        ]
    ),
    supported_rule!(
        &[
            "map_value_or_null",
            "ptr_or_null",
            "mem_or_null",
            "possibly null"
        ],
        ProofObligation::NullablePointer,
        "BPFIX-E002",
        "source_bug",
        "nullable pointer proof is missing",
        &[
            "Add an explicit null check and keep the dereference inside the non-null branch.",
            "Avoid copying the nullable value through a path that loses the verifier's refined type.",
        ]
    ),
    supported_rule!(
        &[
            "invalid read from stack",
            "invalid indirect read from stack",
            "invalid write to stack",
            "uninitialized",
            "!read_ok"
        ],
        ProofObligation::StackInitialized,
        "BPFIX-E003",
        "source_bug",
        "stack initialization proof is missing",
        &[
            "Initialize the full stack object before the helper call or load.",
            "Reduce the helper length argument so it covers only initialized bytes.",
        ]
    ),
    supported_rule!(
        &["unreleased reference", "reference has not been released"],
        ProofObligation::ReferenceLifecycle,
        "BPFIX-E004",
        "source_bug",
        "reference lifecycle proof is missing",
        &[
            "Call the matching release helper before each return.",
            "Restructure error paths so acquired references share one cleanup block.",
        ]
    ),
    supported_rule!(
        &["misaligned", "not aligned"],
        ProofObligation::Alignment,
        "BPFIX-E007",
        "source_bug",
        "memory alignment proof is missing",
        &[
            "Align the object or access it with a smaller load/store size that matches the verifier-proven alignment.",
            "Avoid pointer arithmetic that hides the final aligned offset from the verifier.",
        ]
    ),
    supported_rule!(
        &[
            "caller passes invalid args",
            "invalid args",
            "invalid argument",
            "bad argument",
            "arg#",
            "helper access to the packet is not allowed",
            "cannot call exception cb directly",
            "only read from"
        ],
        ProofObligation::HelperArgument,
        "BPFIX-E010",
        "source_bug",
        "helper or subprogram argument contract is not satisfied",
        &[
            "Check the exact register passed as each helper or subprogram argument.",
            "Keep argument range, nullability, and pointer type refinements visible at the call site.",
        ]
    ),
    supported_rule!(
        &["access beyond struct"],
        ProofObligation::ContextAccess,
        "BPFIX-E011",
        "source_bug",
        "context or kernel-struct field access is invalid",
        &[
            "Check the BTF type, program context type, and field offset used by the access.",
            "Use CO-RE field access helpers or a program type whose context exposes the requested field.",
        ]
    ),
    triage_rule!(
        &[
            "invalid bpf_context access",
            "invalid ctx access",
            "invalid access to context"
        ],
        ProofObligation::ContextAccess,
        "BPFIX-E011",
        "environment_or_configuration",
        "program context field is unavailable",
        &[
            "Check the section name, program type, and attach type used by the loader.",
            "Use only context fields documented for this program type, or move the logic to a compatible hook.",
        ]
    ),
    supported_rule!(
        &["unsupported reg type"],
        ProofObligation::TypeContract,
        "BPFIX-E008",
        "source_bug",
        "verifier-visible type does not match the API contract",
        &[
            "Check whether this helper or kfunc accepts stack, packet, map-value, context, or dynptr-backed memory.",
            "Move the value into a verifier-supported storage class before passing it to the call.",
        ]
    ),
    triage_rule!(
        &["jit does not support", "unsupported", "unknown opcode"],
        ProofObligation::InstructionSupport,
        "BPFIX-E016",
        "environment_or_configuration",
        "kernel, JIT, or instruction-set support is unavailable",
        &[
            "Check the target kernel version, JIT support, and compiler flags used for this object.",
            "Regenerate the BPF object for a supported instruction set or disable the unsupported feature path.",
        ]
    ),
    triage_rule!(
        &["calling kernel function"],
        ProofObligation::EnvironmentCapability,
        "BPFIX-E009",
        "environment_or_configuration",
        "kernel or program-type capability is unavailable",
        &[
            "Check kernel version, program type, attach type, capabilities, and BTF availability.",
            "Use a supported helper or gate the code path by target kernel capabilities.",
        ]
    ),
    ClassRule {
        any: &[],
        all: &["type=", "expected="],
        class: Classification {
            error_id: "BPFIX-E008",
            failure_class: "source_bug",
            summary: "verifier-visible type does not match the required type",
            required_proof: ProofObligation::TypeContract.default_required_proof(),
            help: &[
                "Avoid casts, arithmetic, or spills that convert the required pointer-like value into a scalar.",
                "Pass the verifier-tracked value directly, or rederive it from a checked base immediately before use.",
            ],
            confidence: "medium",
            diagnostic_kind: "supported",
            help_safety: "repair_hint",
        },
    },
    supported_rule!(
        &[
            "expected pointer",
            "expected=fp",
            "expected=pkt",
            "expected=map_ptr",
            "expected=map_value"
        ],
        ProofObligation::TypeContract,
        "BPFIX-E008",
        "source_bug",
        "verifier-visible type does not match the required type",
        &[
            "Avoid casts, arithmetic, or spills that convert the required pointer-like value into a scalar.",
            "Pass the verifier-tracked value directly, or rederive it from a checked base immediately before use.",
        ]
    ),
    supported_rule!(
        &["dynptr"],
        ProofObligation::DynptrSafety,
        "BPFIX-E012",
        "source_bug",
        "dynptr lifetime or bounds proof is missing",
        &[
            "Revalidate dynptr slice nullability and length before use.",
            "Do not reuse a dynptr slice after an operation that invalidates it.",
        ]
    ),
    supported_rule!(
        &["kfunc", "trusted", "ref_obj_id", "acquire", "has no valid kptr"],
        ProofObligation::KfuncReference,
        "BPFIX-E013",
        "source_bug",
        "kfunc trusted-pointer or reference contract is not satisfied",
        &[
            "Check whether the kfunc requires a trusted, non-null, or referenced pointer.",
            "Release acquired references on every exit path and avoid reusing invalidated references.",
        ]
    ),
    supported_rule!(
        &["iter", "iterator"],
        ProofObligation::IteratorLifecycle,
        "BPFIX-E014",
        "source_bug",
        "iterator lifecycle proof is missing",
        &[
            "Destroy iterator state on all exit paths.",
            "Do not read iterator-owned state after the verifier-visible destroy or invalidation point.",
        ]
    ),
    supported_rule!(
        &["irq", "rcu", "lock"],
        ProofObligation::LockState,
        "BPFIX-E015",
        "source_bug",
        "lock, RCU, or IRQ state discipline is violated",
        &[
            "Keep acquire and release operations balanced on every path.",
            "Avoid restoring IRQ or lock state out of order across branches and callbacks.",
        ]
    ),
    supported_rule!(
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
            "invalid access to memory"
        ],
        ProofObligation::ScalarRange,
        "BPFIX-E005",
        "source_bug",
        "scalar range proof is missing",
        &[
            "Clamp the index or length with explicit upper and lower bounds.",
            "Keep the bounded scalar in the same SSA value used for pointer arithmetic or helper length.",
        ]
    ),
    supported_rule!(
        &[
            "invalid mem access 'scalar'",
            "same insn cannot be used with different pointers",
            "pointer arithmetic",
            "dereference of modified ctx ptr"
        ],
        ProofObligation::PointerProvenance,
        "BPFIX-E006",
        "source_bug",
        "pointer type proof is missing",
        &[
            "Avoid integer casts or arithmetic that turn the pointer into a scalar before the access.",
            "Recompute the pointer from a verifier-tracked base after scalar manipulation.",
        ]
    ),
    supported_rule!(
        &["loop is not bounded", "infinite loop detected", "back-edge"],
        ProofObligation::LoopBound,
        "BPFIX-E018",
        "source_bug",
        "loop bound proof is missing",
        &[
            "Add a constant upper bound or clamp the loop induction variable before the loop.",
            "Avoid data-dependent back edges that the verifier cannot prove will terminate.",
        ]
    ),
    supported_rule!(
        &[
            "too many states",
            "bpf program is too large",
            "combined stack size",
            "complexity",
            "combined stack",
            "processed 1000001 insn"
        ],
        ProofObligation::VerifierLimit,
        "BPFIX-E018",
        "verifier_limit",
        "verifier resource limit was reached",
        &[
            "Add a constant loop bound or split complex control flow into smaller helper programs.",
            "For combined stack-size errors, reduce stack usage across caller, subprogram, and callback frames.",
            "Reduce path-sensitive state by simplifying branches and stack state carried through the loop.",
        ]
    ),
    triage_rule!(
        &[
            "unknown func",
            "helper call is not allowed",
            "program of this type cannot use helper",
            "cannot use helper",
            "missing btf",
            "cannot call",
            "permission denied"
        ],
        ProofObligation::EnvironmentCapability,
        "BPFIX-E009",
        "environment_or_configuration",
        "kernel or program-type capability is unavailable",
        &[
            "Check kernel version, program type, attach type, capabilities, and BTF availability.",
            "Use a supported helper or gate the code path by target kernel capabilities.",
        ]
    ),
];

pub(crate) fn classify(message: &str) -> Classification {
    let lower = message.to_ascii_lowercase();
    if let Some(rule) = CLASS_RULES.iter().find(|rule| rule.matches(&lower)) {
        return rule.class;
    }
    triage_class(
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
