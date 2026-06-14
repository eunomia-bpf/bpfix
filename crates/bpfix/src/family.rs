#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofObligation {
    PacketBounds,
    PointerProvenance,
    ScalarRange,
    NullablePointer,
    StackInitialized,
    ReferenceLifecycle,
    Alignment,
    TypeContract,
    HelperArgument,
    ContextAccess,
    VerifierLimit,
    EnvironmentCapability,
    DynptrSafety,
    KfuncReference,
    IteratorLifecycle,
    LockState,
    InstructionSupport,
    LoopBound,
    Unknown,
}

impl ProofObligation {
    pub const fn context_label(self) -> &'static str {
        match self {
            Self::PacketBounds => "packet bounds",
            Self::PointerProvenance => "pointer provenance",
            Self::ScalarRange => "scalar range",
            Self::NullablePointer => "nullable pointer",
            Self::StackInitialized => "stack initialization",
            Self::ReferenceLifecycle => "reference lifecycle",
            Self::Alignment => "alignment",
            Self::TypeContract => "type contract",
            Self::HelperArgument => "helper/subprogram argument",
            Self::ContextAccess => "context/struct access",
            Self::VerifierLimit => "verifier limit",
            Self::EnvironmentCapability => "environment/capability",
            Self::DynptrSafety => "dynptr safety",
            Self::KfuncReference => "kfunc/reference",
            Self::IteratorLifecycle => "iterator lifecycle",
            Self::LockState => "lock/RCU/IRQ state",
            Self::InstructionSupport => "instruction support",
            Self::LoopBound => "loop bound",
            Self::Unknown => "verifier proof",
        }
    }

    pub const fn default_required_proof(self) -> &'static str {
        match self {
            Self::PacketBounds => {
                "prove that the packet pointer plus requested access size stays before data_end on every path reaching the load, store, or helper call"
            }
            Self::PointerProvenance => {
                "preserve a verifier-recognized pointer type at the operation that requires a pointer"
            }
            Self::ScalarRange => {
                "bound the scalar value tightly enough for the verifier to prove the memory access range"
            }
            Self::NullablePointer => {
                "prove that the nullable pointer returned by a helper is checked for null before dereference or helper reuse"
            }
            Self::StackInitialized => {
                "initialize every stack byte that can be read directly or passed indirectly to a helper"
            }
            Self::ReferenceLifecycle => {
                "release every acquired verifier-tracked reference on every exit path"
            }
            Self::Alignment => {
                "prove that the stack, packet, or map-value address has the alignment required for this access size"
            }
            Self::TypeContract => {
                "preserve the pointer, frame-pointer, map, packet, trusted, or other verifier-visible type required by this instruction or helper argument"
            }
            Self::HelperArgument => {
                "pass verifier-recognized argument types, ranges, and pointer lifetimes to the helper, kfunc, or subprogram"
            }
            Self::ContextAccess => {
                "access only fields and offsets that are valid for the verifier-visible context or kernel struct type"
            }
            Self::VerifierLimit => {
                "reduce verifier state growth or provide a statically bounded loop shape"
            }
            Self::EnvironmentCapability => {
                "load the program with a kernel, program type, attach point, and privileges that support the requested helper or kfunc"
            }
            Self::DynptrSafety => {
                "keep dynptr slices inside their proven lifetime, initialized range, and read/write mode"
            }
            Self::KfuncReference => {
                "satisfy the kfunc trusted argument, nullability, and acquire/release contract on every path"
            }
            Self::IteratorLifecycle => {
                "keep iterator state inside the verifier-approved create, next, and destroy lifecycle"
            }
            Self::LockState => {
                "preserve the verifier-required ordering for lock, RCU, or IRQ state acquire and release operations"
            }
            Self::InstructionSupport => {
                "use a kernel, JIT configuration, and compiler target that support the generated BPF instruction stream"
            }
            Self::LoopBound => {
                "make the loop bound statically visible and small enough for the verifier"
            }
            Self::Unknown => {
                "inspect the terminal verifier line and add the missing safety proof required at that program point"
            }
        }
    }

    pub const fn rejected_detail(self) -> &'static str {
        match self {
            Self::PacketBounds => {
                "rejected here: packet access is not proven to stay before data_end"
            }
            Self::PointerProvenance => {
                "rejected here: verifier sees a scalar where a pointer is required"
            }
            Self::ScalarRange => {
                "rejected here: scalar range is not proven safe for this memory operation"
            }
            Self::NullablePointer => {
                "rejected here: nullable pointer is used without a visible non-null proof"
            }
            Self::StackInitialized => "rejected here: stack bytes are not proven initialized",
            Self::ReferenceLifecycle => {
                "rejected here: reference is not proven released on all paths"
            }
            Self::Alignment => "rejected here: memory access alignment is not proven",
            Self::TypeContract => {
                "rejected here: verifier-visible value type does not match this operation"
            }
            Self::HelperArgument => {
                "rejected here: helper or subprogram argument contract is not satisfied"
            }
            Self::ContextAccess => {
                "rejected here: requested context or kernel-struct field is not available"
            }
            Self::VerifierLimit => {
                "rejected here: verifier analysis budget or loop proof is exhausted"
            }
            Self::EnvironmentCapability => {
                "rejected here: kernel or program type does not expose this capability"
            }
            Self::DynptrSafety => "rejected here: dynptr lifetime or bounds proof is missing",
            Self::KfuncReference => {
                "rejected here: kfunc trusted-pointer or reference contract is not satisfied"
            }
            Self::IteratorLifecycle => "rejected here: iterator lifecycle proof is missing",
            Self::LockState => "rejected here: lock, RCU, or IRQ state discipline is violated",
            Self::InstructionSupport => {
                "rejected here: kernel or JIT does not support this instruction or feature"
            }
            Self::LoopBound => "rejected here: loop bound proof is missing",
            Self::Unknown => "rejected here: required verifier proof is missing",
        }
    }
}
