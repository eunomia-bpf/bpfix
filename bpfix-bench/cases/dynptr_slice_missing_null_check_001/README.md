# dynptr_slice_missing_null_check_001

The program converts the XDP packet to a dynptr and asks `bpf_dynptr_slice()`
for the Ethernet header. The slice result is nullable, but the program reads
`h_proto` before proving the returned memory pointer is non-null.

This is a modern BPF nullable-helper case. A correct repair must keep the
dynptr slice path, add the missing null check, and preserve IPv4 drop,
non-IPv4 pass, and short-packet pass behavior.
