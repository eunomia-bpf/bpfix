# rs_xdp_tools_load_bytes_stack_len_001

Real-project seed from xdp-tools' `xdp_load_bytes.bpf.c` helper probe.
The case preserves the helper-based XDP byte-load workflow, but the buggy
program asks `bpf_xdp_load_bytes` to write more bytes than the stack scratch
buffer can hold.

The intended repair is to keep the helper path and make the helper length match
the stack buffer that the later marker check reads.
