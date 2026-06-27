# xdp_adjust_head_map_value_001

The program validates an Ethernet/IPv4 packet, looks up a map value, calls
`bpf_xdp_adjust_head()` to remove the Ethernet header, and then reuses the old
`iph` packet pointer while updating the map value.

The verifier rejects the stale packet pointer after the helper invalidates prior
packet state:

```text
invalid mem access 'scalar'
```

A working repair must reload `ctx->data` and `ctx->data_end` after
`bpf_xdp_adjust_head()`, rederive the IPv4 header at the new packet start, keep
the map-value null check, update `seen_packets`, and preserve the map-driven UDP
drop / TCP pass behavior.
