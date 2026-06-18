# rs_agentsight_process_ringbuf_null_001

Source: real project seed from `agentsight` commit `77a7ea3`,
`bpf/process.bpf.c`, license `GPL-2.0 OR BSD-3-Clause`.

The upstream process tracer reserves a ring-buffer event, fills process metadata,
and submits it. This minimized candidate keeps the same event-emission shape in a
TC test harness so `bpftool prog run` can provide a deterministic oracle. The
buggy version writes to the reserved event before proving that
`bpf_ringbuf_reserve()` returned non-null.

A correct repair must add the null check and keep the event write and submit
path. Returning the right TC action without submitting the event is not enough.
