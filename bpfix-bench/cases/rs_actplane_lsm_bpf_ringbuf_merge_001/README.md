# rs_actplane_lsm_bpf_ringbuf_merge_001

Source: real project seed from `ActPlane` commit `84169ce`,
`bpf/process.bpf.c`, license `GPL-2.0 OR BSD-3-Clause`.

The upstream ActPlane BPF program enforces LSM policy, checks protected process
state in maps, and emits violation events through a ring buffer. This minimized
candidate keeps that LSM policy shape: it checks a protected-pid map, reserves a
ring-buffer event, records the current process and BPF command, and denies the
operation.

The bug is a proof-lifecycle error in the ring-buffer reserve path. The program
only returns on `!event && privileged`, so the verifier reaches the event write
with `event` still typed as `ringbuf_mem_or_null` on the unprivileged branch.

A correct repair must prove the ring-buffer pointer is non-null before writing
the event, while preserving the LSM hook, protected-pid map lookup, event
submission, and deny return. Deleting the event path, turning the hook into XDP,
or allowing all BPF operations is not a valid repair.
