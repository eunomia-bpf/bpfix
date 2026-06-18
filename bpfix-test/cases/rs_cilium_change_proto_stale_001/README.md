# rs_cilium_change_proto_stale_001

Source: real project seed from `cilium` commit `3a364638`,
`bpf/bpf_overlay.c`, license `GPL-2.0-only OR BSD-2-Clause`.

Cilium's overlay datapath repeatedly revalidates `data` and `data_end` before
using packet headers after load-balancing, encapsulation, or delivery helpers
may have rewritten packet state. This minimized candidate keeps that production
packet-rewrite/provenance shape in a deterministic TC harness. The buggy version
calls `bpf_skb_change_proto()` and then writes through the stale pre-helper
packet pointer.

A correct repair must reload `skb->data` and `skb->data_end`, re-check the
Ethernet header bounds, and keep the post-helper Ethernet protocol rewrite.
Returning the right TC action without the helper and post-helper packet write is
not enough.
