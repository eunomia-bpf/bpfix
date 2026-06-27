# dynptr_stack_copy_001

The program initializes an XDP dynptr and then copies the dynptr stack storage
with `__builtin_memcpy()` into another stack slot before calling
`bpf_dynptr_slice()` on the copy.

This is a modern BPF object protocol case. A correct repair must pass the exact
verifier-tracked dynptr slot to later helpers instead of copying dynptr storage
as ordinary bytes, while preserving packet behavior.
