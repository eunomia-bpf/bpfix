# dynptr_slice_short_mem_001

The program asks `bpf_dynptr_slice()` for only 13 bytes from the packet and
then treats the result as a full Ethernet header, reading the 2-byte `h_proto`
field at offset 12.

This is a dynptr memory-object bounds case. A correct repair must request a
slice large enough for the field being read, keep the null check, and preserve
IPv4 drop, non-IPv4 pass, and short-packet pass behavior.
