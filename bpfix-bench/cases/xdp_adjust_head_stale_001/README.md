# xdp_adjust_head_stale_001

Canary bucket: proof lifecycle / helper side effect.

The program validates an Ethernet/IPv4 packet, calls `bpf_xdp_adjust_head()`,
and then accidentally keeps using packet pointers loaded before the helper call.
The helper invalidates verifier packet pointer state, so the final raw log points
at a later packet read:

```text
R6 invalid mem access 'scalar'
```

A working repair must avoid using packet pointers invalidated by
`bpf_xdp_adjust_head()`. Recomputing packet pointers after the helper and
carrying only scalar decisions across the helper are both accepted when the
observable behavior is preserved. The oracle requires the successful verifier
trace to contain the helper call, then runs UDP and TCP packet tests.
