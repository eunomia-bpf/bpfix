# rs_eunomia_wq_container_map_001

Real-project seed candidate from `eunomia.dev`
`docs/tutorials/features/bpf_wq/wq_simple.bpf.c`.

The upstream tutorial demonstrates the BPF workqueue lifecycle: store an element
with an embedded `struct bpf_wq` in a map, initialize the workqueue with the
containing map, register an async callback, and then start the workqueue. This
minimized case keeps that lifecycle in a deterministic XDP harness so the test
can exercise real packet inputs while still preserving the modern kfunc
protocol.

The injected bug copies the workqueue lifecycle shape but points `bpf_wq_init`
at a stack-local `struct bpf_wq`. The rejected line is the kfunc call, but a
useful repair has to understand the map-value ownership contract: the verifier
requires the workqueue pointer to come from a map value that embeds
`struct bpf_wq`, not from ordinary stack storage.

A correct repair must use the `work_items` map-backed element's embedded
workqueue, pass the containing map to `bpf_wq_init`, register the callback
before `bpf_wq_start`, keep the schedule accounting map updates, and still
return the same packet verdicts for malformed, skipped, and scheduled packets.
