//! Small helper ABI facts used by verifier-log diagnostics.
//!
//! These functions model stable helper argument positions. They intentionally
//! answer narrow questions instead of trying to describe every helper contract.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelperMemoryArgPair {
    pub ptr_reg: u8,
    pub len_reg: u8,
}

impl HelperMemoryArgPair {
    const fn new(ptr_reg: u8, len_reg: u8) -> Self {
        Self { ptr_reg, len_reg }
    }
}

pub fn helper_probe_read_value_pair(target: &str) -> Option<HelperMemoryArgPair> {
    match target {
        "bpf_probe_read"
        | "4"
        | "bpf_probe_read_user"
        | "112"
        | "bpf_probe_read_kernel"
        | "113" => Some(HelperMemoryArgPair::new(1, 2)),
        _ => None,
    }
}

pub fn helper_stack_output_pair(target: &str) -> Option<HelperMemoryArgPair> {
    match target {
        "bpf_probe_read"
        | "4"
        | "bpf_probe_read_user"
        | "112"
        | "bpf_probe_read_kernel"
        | "113"
        | "bpf_probe_read_str"
        | "45"
        | "bpf_probe_read_user_str"
        | "114"
        | "bpf_probe_read_kernel_str"
        | "115"
        | "bpf_get_current_comm"
        | "16"
        | "bpf_copy_from_user"
        | "bpf_copy_from_user_task"
        | "bpf_dynptr_read"
        | "bpf_snprintf" => Some(HelperMemoryArgPair::new(1, 2)),
        "bpf_d_path" | "bpf_get_stack" | "bpf_get_task_stack" => {
            Some(HelperMemoryArgPair::new(2, 3))
        }
        "bpf_skb_load_bytes" | "26" | "bpf_skb_load_bytes_relative" | "bpf_xdp_load_bytes" => {
            Some(HelperMemoryArgPair::new(3, 4))
        }
        _ => None,
    }
}

pub fn helper_stack_read_pair(target: &str) -> Option<HelperMemoryArgPair> {
    match target {
        "bpf_dynptr_slice" | "bpf_dynptr_slice_rdwr" => Some(HelperMemoryArgPair::new(3, 4)),
        _ => None,
    }
}

pub fn helper_writable_stack_output_pair(target: &str) -> Option<HelperMemoryArgPair> {
    match target {
        "bpf_get_current_comm" => Some(HelperMemoryArgPair::new(1, 2)),
        _ => None,
    }
}

pub fn helper_map_value_memory_access_pair(target: &str) -> Option<HelperMemoryArgPair> {
    match target {
        "bpf_probe_read"
        | "bpf_probe_read_kernel"
        | "bpf_probe_read_kernel_str"
        | "bpf_probe_read_user"
        | "bpf_probe_read_user_str" => Some(HelperMemoryArgPair::new(1, 2)),
        _ => None,
    }
}

pub fn helper_scalar_length_register(target: &str) -> Option<u8> {
    match target {
        "bpf_probe_read"
        | "bpf_probe_read_kernel"
        | "bpf_probe_read_kernel_str"
        | "bpf_probe_read_user"
        | "bpf_probe_read_user_str" => Some(2),
        "bpf_csum_diff" => Some(4),
        "bpf_skb_load_bytes" => Some(4),
        "bpf_perf_event_output" => Some(5),
        _ => None,
    }
}

pub fn helper_consumes_scalar_length_register(target: &str, reg: u8) -> bool {
    helper_scalar_length_register(target) == Some(reg)
        || matches!(target, "bpf_csum_diff") && matches!(reg, 2 | 4)
}

pub fn helper_dynptr_initializer_output_arg(target: &str) -> Option<u8> {
    match target {
        "bpf_ringbuf_reserve_dynptr" | "bpf_dynptr_from_mem" => Some(4),
        "bpf_dynptr_from_skb" | "bpf_dynptr_from_xdp" => Some(3),
        _ => None,
    }
}

pub fn helper_dynptr_live_arg(target: &str) -> Option<u8> {
    match target {
        "bpf_dynptr_data"
        | "bpf_dynptr_clone"
        | "bpf_ringbuf_discard_dynptr"
        | "bpf_ringbuf_submit_dynptr" => Some(1),
        "bpf_dynptr_read" | "bpf_dynptr_write" => Some(3),
        _ => None,
    }
}

pub fn helper_dynptr_initialized_arg(target: &str) -> Option<u8> {
    match target {
        "bpf_dynptr_data"
        | "bpf_dynptr_clone"
        | "bpf_dynptr_slice"
        | "bpf_dynptr_slice_rdwr"
        | "bpf_ringbuf_discard_dynptr"
        | "bpf_ringbuf_submit_dynptr" => Some(1),
        "bpf_dynptr_read" | "bpf_dynptr_write" => Some(3),
        _ => None,
    }
}

pub fn helper_dynptr_data_producer_arg(target: &str) -> Option<u8> {
    matches!(
        target,
        "bpf_dynptr_data" | "bpf_dynptr_slice" | "bpf_dynptr_slice_rdwr"
    )
    .then_some(1)
}

pub fn helper_dynptr_data_invalidating_arg(target: &str) -> Option<u8> {
    match target {
        "bpf_dynptr_write" => Some(1),
        "bpf_dynptr_from_mem" => Some(4),
        "bpf_dynptr_from_skb" | "bpf_dynptr_from_xdp" => Some(3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_probe_read_and_stack_output_pairs() {
        assert_eq!(
            helper_probe_read_value_pair("bpf_probe_read_kernel"),
            Some(HelperMemoryArgPair::new(1, 2))
        );
        assert_eq!(
            helper_stack_output_pair("bpf_skb_load_bytes"),
            Some(HelperMemoryArgPair::new(3, 4))
        );
        assert_eq!(
            helper_stack_output_pair("16"),
            Some(HelperMemoryArgPair::new(1, 2))
        );
    }

    #[test]
    fn keeps_narrow_stack_read_and_write_contracts() {
        assert_eq!(
            helper_stack_read_pair("bpf_dynptr_slice_rdwr"),
            Some(HelperMemoryArgPair::new(3, 4))
        );
        assert_eq!(
            helper_writable_stack_output_pair("bpf_get_current_comm"),
            Some(HelperMemoryArgPair::new(1, 2))
        );
        assert_eq!(
            helper_writable_stack_output_pair("bpf_probe_read_kernel"),
            None
        );
    }

    #[test]
    fn exposes_scalar_length_consumers() {
        assert_eq!(
            helper_scalar_length_register("bpf_perf_event_output"),
            Some(5)
        );
        assert!(helper_consumes_scalar_length_register("bpf_csum_diff", 2));
        assert!(helper_consumes_scalar_length_register("bpf_csum_diff", 4));
        assert!(!helper_consumes_scalar_length_register("bpf_csum_diff", 5));
    }

    #[test]
    fn exposes_dynptr_argument_roles() {
        assert_eq!(
            helper_dynptr_initializer_output_arg("bpf_dynptr_from_skb"),
            Some(3)
        );
        assert_eq!(
            helper_dynptr_initializer_output_arg("bpf_dynptr_from_mem"),
            Some(4)
        );
        assert_eq!(helper_dynptr_live_arg("bpf_dynptr_write"), Some(3));
        assert_eq!(
            helper_dynptr_initialized_arg("bpf_dynptr_slice_rdwr"),
            Some(1)
        );
        assert_eq!(helper_dynptr_data_producer_arg("bpf_dynptr_slice"), Some(1));
        assert_eq!(
            helper_dynptr_data_invalidating_arg("bpf_dynptr_write"),
            Some(1)
        );
    }
}
