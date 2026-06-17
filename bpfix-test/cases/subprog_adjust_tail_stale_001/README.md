# subprog_adjust_tail_stale_001

The packet pointer is checked in the caller, but the packet-mutating
`bpf_xdp_adjust_tail()` call is hidden in a `__noinline` subprogram. After the
subprogram returns, the caller reuses the stale Ethernet pointer.

This is a source/call-correlation stale pointer case. A correct repair must keep
the subprogram tail adjustment, then reload and recheck packet pointers in the
caller before reading the Ethernet header.
