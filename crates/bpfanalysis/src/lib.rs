#![allow(dead_code)]

//! eBPF bytecode and verifier-log analysis primitives.
//!
//! The core analysis modules are imported from the `bpfopt` project and kept
//! behind a small public surface that is useful for user-facing diagnostics.

pub mod analysis;
pub mod insn;
pub mod object_file;
pub mod pass;
pub mod passes;

mod verifier_log;

pub use object_file::{load_object_cfg_summaries, ObjectProgramSummary};
pub use verifier_log::{
    verifier_states_from_log, RegState, ScalarRange, StackState, Tnum, VerifierInsn,
    VerifierInsnKind, VerifierValueWidth,
};

#[cfg(test)]
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
