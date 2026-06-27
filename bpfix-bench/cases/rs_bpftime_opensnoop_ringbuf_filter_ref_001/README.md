# rs_bpftime_opensnoop_ringbuf_filter_ref_001

This candidate is a minimized real-project seed from
`bpftime/example/tracing/opensnoop_ring_buf/opensnoop.bpf.c`.

The upstream program stores open/openat arguments on syscall entry and emits a
ring-buffer event on syscall exit. This case keeps that two-stage tracepoint
workflow but injects a reference-lifecycle bug: the exit program reserves a
ring-buffer record, then applies a return-value filter and returns directly on
the filtered path. That path leaves the verifier-tracked ring-buffer reference
live and also bypasses deletion of the saved syscall-entry arguments.

The verifier rejects the buggy program with an unreleased reference at exit. A
correct repair must preserve the tracepoint workflow, the `start` map lookup and
cleanup, the user filename copy, and ring-buffer event submission while ensuring
every path after `bpf_ringbuf_reserve` either submits or discards the reserved
record before exit.
