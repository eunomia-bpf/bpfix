# ringbuf_stack_submit_001

Canary bucket: modern BPF helper protocol.

The buggy source builds an event on the stack and passes `&ev` to
`bpf_ringbuf_submit()`. The helper contract requires a `ringbuf_mem` pointer
returned by `bpf_ringbuf_reserve()`, not an arbitrary stack pointer.

The raw verifier log rejects the helper call:

```text
R1 type=fp expected=ringbuf_mem
```

A working repair must reserve ringbuf memory, check the nullable return, write
the event into that memory, and submit exactly that pointer. The oracle loads the
candidate as XDP, checks that the successful verifier trace contains
`bpf_ringbuf_reserve`, `ringbuf_mem_or_null`, a `u32` store into `ringbuf_mem`,
and `bpf_ringbuf_submit`, then runs a packet test that must return `XDP_PASS`.
A candidate that deletes the ringbuf operation or submits an unwritten reserved
record does not pass.
