# xdp_adjust_tail_stale_001

The program reads the packet pointers, trims four bytes from the tail with
`bpf_xdp_adjust_tail()`, and then reuses the old Ethernet pointer.

This is a helper side-effect / stale packet pointer case. A correct repair must
keep the tail adjustment, reload `ctx->data` and `ctx->data_end`, recheck the
Ethernet header, and preserve IPv4 drop, non-IPv4 pass, and short-packet pass
behavior.
