# dynptr_uninitialized_slice_arg_001

The program declares a `struct bpf_dynptr` stack slot and passes it directly to
`bpf_dynptr_slice()` without first creating an XDP dynptr.

This tests modern BPF object protocol state. A correct repair must initialize
the dynptr with `bpf_dynptr_from_xdp()` before slicing it, keep the slice null
check, and preserve IPv4 drop, non-IPv4 pass, and short-packet pass behavior.
