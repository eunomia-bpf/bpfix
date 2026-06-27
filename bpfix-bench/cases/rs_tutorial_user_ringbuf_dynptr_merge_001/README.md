# rs_tutorial_user_ringbuf_dynptr_merge_001

This candidate is a minimized real-project seed from
`bpf-developer-tutorial/src/35-user-ringbuf/user_ringbuf.bpf.c`.

The upstream program demonstrates the user-ringbuf workflow: userspace writes
samples into a `BPF_MAP_TYPE_USER_RINGBUF`; a tracepoint program drains those
samples through a dynptr callback; the callback emits a kernel-ringbuf event
back to userspace. This minimized case keeps that workflow and adds a small
payload-copy step inside the callback so the verifier must reason about the
user-ringbuf dynptr payload, not just the drain helper itself.

This case keeps that workflow but injects a dynptr proof-lifecycle bug. The
callback obtains a payload pointer with `bpf_dynptr_data`, checks it only on the
`current_pid == 0` path, and then reads `msg->op` and `msg->comm` after the
branch merge. On the other path the verifier still sees `msg` as
`mem_or_null`, so the load is rejected.

A correct repair must make the dynptr payload proof dominate every later payload
read while preserving the user-ringbuf drain, kernel-ringbuf reserve/submit,
PID attribution, and the injected payload-to-event copy.
