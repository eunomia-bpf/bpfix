# rs_tutorial_dynptr_tc_ref_leak_001

This candidate is a minimized real-project seed from
`bpf-developer-tutorial/src/features/dynptr/dynptr_tc.bpf.c`.

The upstream program demonstrates TC packet parsing with `bpf_dynptr_from_skb`,
`bpf_dynptr_slice`, `bpf_dynptr_read`, and variable-length ring-buffer dynptr
records. This case keeps that workflow but injects a reference-lifecycle bug:
after `bpf_ringbuf_reserve_dynptr`, the reserve-error path and the first
`bpf_dynptr_write` error path can return without calling
`bpf_ringbuf_discard_dynptr` or `bpf_ringbuf_submit_dynptr`.

The verifier rejects the buggy program with an unreleased dynptr ring-buffer
reference at exit. A correct repair must preserve TC packet parsing, the
config-map driven drop policy, payload snapshot reads, ring-buffer dynptr
reserve/write, submit on success, and discard on every reserve/write failure
path. The oracle uses packet-run return values for the TC policy and successful
verifier-log predicates for the dynptr helper protocol because ring-buffer
records are not observable through `bpftool prog run`.
