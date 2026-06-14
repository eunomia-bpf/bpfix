#![allow(dead_code)]

//! eBPF bytecode and verifier-log analysis primitives.
//!
//! The core analysis modules are imported from the `bpfopt` project and kept
//! behind a small public surface that is useful for user-facing diagnostics.
//! The optional `cli` feature only enables `clap` derives for pass-runner
//! integrations; log parsing and object analysis do not need it.

#[cfg(feature = "analysis")]
pub mod analysis;
#[cfg(feature = "analysis")]
pub mod insn;
#[cfg(feature = "object-analysis")]
pub mod object_file;
#[cfg(feature = "analysis")]
pub mod pass;
#[cfg(feature = "analysis")]
pub mod passes;

mod verifier_log;

#[cfg(feature = "object-analysis")]
pub use object_file::{load_object_cfg_summaries, ObjectProgramSummary};
pub use verifier_log::{
    verifier_states_from_log, verifier_states_with_branch_deltas_from_log, RegState, ScalarRange,
    StackState, Tnum, VerifierInsn, VerifierInsnKind, VerifierValueWidth,
};

#[cfg(all(test, feature = "analysis"))]
pub(crate) mod test_helpers;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierLogSummary {
    pub state_count: usize,
}

pub fn summarize_verifier_log(log: &str) -> anyhow::Result<VerifierLogSummary> {
    Ok(VerifierLogSummary {
        state_count: verifier_log::verifier_states_from_log(log)?.len(),
    })
}
