# rs_actplane_policy_map_merge_001

Source: real project seed from `ActPlane` commit `5e9cbaba`,
`bpf/process.bpf.c`, license `GPL-2.0 OR BSD-3-Clause`.

The upstream policy engine stores runtime policy state in BPF maps and makes
decisions after checking context-derived attributes. This minimized candidate
keeps the map-backed policy decision shape in a TC test harness. The buggy
version only proves the hash-map lookup is non-null on the IPv4 branch, then
uses the same policy pointer after the branch merge.

A correct repair must keep the map lookup, state update, and two packet
outcomes while making the map-value proof visible on every path that reads it.
