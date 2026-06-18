# rs_agentsight_write_ctx_merge_001

Source: real project seed from `agentsight` commit
`e758c69761c52abd16eefdc8dded6643f5669bdb`,
`bpf/process_ext/bpf_write.h`, license `GPL-2.0 OR BSD-3-Clause`.
Canonical source:
`https://github.com/eunomia-bpf/agentsight/blob/e758c69761c52abd16eefdc8dded6643f5669bdb/bpf/process_ext/bpf_write.h`.

The upstream AgentSight process-extension tracer pairs write-family syscall
entry and exit hooks through a temporary `write_ctx_map`, deletes that pending
context on syscall exit, and aggregates bytes written into an event aggregate
map. This minimized XDP harness keeps that enter/exit pairing shape so repairs
can be checked with deterministic `bpftool prog run` packets and pinned maps.

This case is a minimized mutation of the workflow, not a claim that upstream
contains this exact bug. The bug checks the pending `write_ctx_map` fd pointer
only on a packet-selected branch, then reads `*fd_ptr` after the branch merge.
The final verifier rejection points at the fd load, while the source-level
cause is that the pending-context proof does not dominate the delete and
aggregate-update workflow.

A correct repair must make the `write_ctx_map` lookup proof dominate the fd
read, delete the pending write context only after a valid exit record, and
aggregate bytes under a key derived from the saved fd. Returning a constant
action, using the packet's decoy fd instead of the saved fd, or dropping the
aggregate update is not a valid repair.
