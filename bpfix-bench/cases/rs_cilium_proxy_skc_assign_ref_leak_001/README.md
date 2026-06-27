# rs_cilium_proxy_skc_assign_ref_leak_001

This candidate is a minimized real-project seed from
`cilium/bpf/lib/proxy.h`.

The upstream Cilium proxy path looks up a socket with
`bpf_skc_lookup_tcp`, assigns it to the skb with `bpf_sk_assign`, and then
releases the looked-up socket with `bpf_sk_release`. This case keeps that
socket-assignment workflow but injects a reference-lifecycle bug: the successful
assign path can return early for a marked packet before releasing the socket
reference returned by `bpf_skc_lookup_tcp`.

The verifier rejects the buggy program with an unreleased socket reference at
exit. A correct repair must preserve the TC program, tuple-based socket lookup,
socket assignment, marked-packet verdict branch, and release of the looked-up
socket on every path after a successful lookup.
