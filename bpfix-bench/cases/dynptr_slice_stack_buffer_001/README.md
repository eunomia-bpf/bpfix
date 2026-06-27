# dynptr_slice_stack_buffer_001

The program creates an XDP dynptr and asks `bpf_dynptr_slice()` to use a stack
scratch buffer. The scratch buffer is only 8 bytes, but the helper is called
with length 9, so verifier state rejects the helper memory/length pair.

This is a modern BPF protocol and stack-range case. A correct repair must make
the stack buffer and helper length agree while preserving the dynptr helper
path: normal packets should drop, very short packets should pass.
