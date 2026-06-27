# xdp_adjust_head_ringbuf_001

This case combines a packet-mutating helper with ringbuf helper protocol. The
program reserves and submits a ringbuf event correctly, but then reuses an old
packet pointer after `bpf_xdp_adjust_head()`.

The oracle requires a repair to preserve the adjust-head helper, ringbuf submit,
and UDP/TCP behavior after the Ethernet header has been stripped.
