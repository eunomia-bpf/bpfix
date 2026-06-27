# rs_actplane_mmap_pending_merge_001

Source: real project seed from ActPlane commit
`84169ce6a22a302afdf64427a0b7ffbab773b6e1`,
`bpf/process.bpf.c`, license `GPL-2.0 OR BSD-3-Clause`.
Canonical source:
`https://github.com/eunomia-bpf/ActPlane/blob/84169ce6a22a302afdf64427a0b7ffbab773b6e1/bpf/process.bpf.c`.
Upstream source sha256:
`c76b74e5890c7d5b6b78eb63a2fca076a18949039e059ef3f0af160fb1125579`.

The upstream path stores mmap syscall-enter state in `ts_mmappend`, consumes it
on syscall exit, resolves an fd reference, writes `ts_mmap`, updates the mmap
index, and deletes the pending entry. This minimized XDP harness preserves that
state-machine shape with packet-provided pid/tid/fd/start values.

This case is a minimized mutation of the mmap-exit workflow, not a claim that
the upstream ActPlane code contains this exact bug. The bug checks the pending
mmap record only on one packet-selected branch, then reads `p->fd` after the
branch merge. On the unchecked path, the verifier still tracks the pending
record as `map_value_or_null`.

A correct repair must establish the pending-record proof before every use,
preserve fd_ref lookup, write the mmap record from the fd_ref and pending
fields, update the mmap index, and delete the pending entry. Returning early,
writing constant mmap state, or deleting the mmap workflow is not a valid
repair.

The positive tests intentionally make the packet fd differ from the fd stored
in `ts_mmappend`. A repair must use `p->fd` for the `ts_fd` lookup; falling back
to the packet fd is treated as a semantic failure even if the program loads.
