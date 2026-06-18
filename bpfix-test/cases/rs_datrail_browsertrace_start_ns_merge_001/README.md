# rs_datrail_browsertrace_start_ns_merge_001

Source: real project seed from `datrail-agent-monitor` commit `cfd94492`,
`bpf/browsertrace.bpf.c`, license `(LGPL-2.1 OR BSD-2-Clause)`.

The upstream browser tracing program records user buffers on syscall entry,
looks them up on syscall exit, computes an elapsed timestamp from a `start_ns`
map value, copies user memory with `bpf_probe_read_user()`, emits a ringbuf
event, and cleans up both maps. This minimized candidate keeps that workflow in
a tracepoint harness.

The bug only proves the `start_ns` lookup is non-null on the `pid == 0` branch,
then computes `delta_ns` from `*tsp` after the branch merge. For normal user
PIDs, the verifier still tracks `tsp` as `map_value_or_null`, so the final
rejection points at the elapsed-time field rather than the earlier proof-loss
branch.

A correct repair must make the `start_ns` proof dominate the elapsed-time use
while preserving the buffer lookup, timestamp delta, bounded user copy, ringbuf
submit, and cleanup of both maps. Replacing the timestamp delta with a constant,
dropping the user-memory copy, or deleting cleanup is not a valid repair.
