mod analyzer;
mod callback_signal;
mod context_signal;
mod dynptr_signal;
mod fallback_pointer_signal;
mod helper_contract_signal;
mod irq_signal;
mod iterator_signal;
mod lowering_signal;
mod map_value_signal;
mod model;
mod nullable_signal;
mod opaque_pointer_signal;
mod packet_signal;
mod proof_events;
mod protocol_signal;
mod scalar_range_signal;
mod shared;
mod signal;
mod signal_pipeline;
mod source_query;
mod stack_access;
mod stack_signal;
mod stale_pointer_signal;
mod type_contract_signal;
#[cfg(test)]
pub use analyzer::analyze_verifier_log;
pub use analyzer::analyze_verifier_log_with_context;
use model::ProofSignalContext;
pub use model::{ProofEvent, ProofEventEvidence, ProofEventRole, VerifierLogContext};
use shared::{
    dynptr_slot_backing_before, dynptr_stack_slot_for_call_argument, is_pointer_state,
    latest_reg_state_before_instruction_with_origin, latest_reg_state_for_call_argument,
    latest_reg_state_for_call_argument_with_frame, latest_register_assignment,
    register_from_terminal_error, terminal_call_instruction_site,
    terminal_error_has_nearby_prior_line, terminal_instruction, terminal_site, DynptrBacking,
    DynptrStackSlot,
};
pub use signal::ProofSignal;

#[cfg(test)]
mod tests;
