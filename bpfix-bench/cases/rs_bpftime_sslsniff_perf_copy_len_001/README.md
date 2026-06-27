# rs_bpftime_sslsniff_perf_copy_len_001

Source: real project seed from `bpftime` commit `3a0572b`,
`example/tracing/sslsniff/sslsniff.bpf.c`, license
`(LGPL-2.1 OR BSD-2-Clause)`.

The upstream SSL sniffer saves a user buffer and start timestamp on function
entry, looks them up on return, fills a per-CPU scratch event, copies user
memory with `bpf_probe_read_user()`, deletes the saved maps, and emits the
event through `bpf_perf_event_output()`.

This candidate preserves that uretprobe/perf-output workflow but makes the
scratch event buffer smaller than the maximum copy size. The verifier rejects
the helper call because the destination map-value range cannot hold the largest
possible copy.

A correct repair must keep the saved-buffer lookup, timestamp delta, bounded
user copy, cleanup, and perf-event output. Dropping the copy or output path is
not a valid repair.
