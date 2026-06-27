# rs_agentsight_stdiocap_user_copy_len_001

Source: real project seed from `agentsight` commit `77a7ea3`,
`bpf/stdiocap.bpf.c`, license `GPL-2.0 OR BSD-3-Clause`.

The upstream stdiocap tracer stores syscall-enter arguments in a map, looks
them up on syscall exit, reserves a ring-buffer event, copies user memory into
the event payload with `bpf_probe_read_user()`, submits the event, and deletes
the pending argument map entry. This minimized case keeps that tracepoint
workflow.

The bug is a helper memory-contract violation. The event has an 8-byte payload
at offset 16, but the program passes a 16-byte length to `bpf_probe_read_user()`.
The verifier rejects the helper call because the destination range extends past
the reserved ring-buffer event.

A correct repair must make the helper length fit the event payload or enlarge
the event payload, while preserving the `io_args` lookup, ring-buffer event,
user-memory copy, submit, and cleanup delete. Deleting the user copy or event
emission is not a valid repair.
