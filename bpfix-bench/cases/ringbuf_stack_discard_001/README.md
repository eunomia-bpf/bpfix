# ringbuf_stack_discard_001

The program creates an event on the stack and passes its address to
`bpf_ringbuf_discard()`. The helper requires a verifier-tracked
`ringbuf_mem` reference returned by `bpf_ringbuf_reserve()`, not a stack
pointer.

This is a helper argument type contract case. A correct repair must reserve a
ringbuf record, write the mark into that record, discard that same record, and
preserve pass behavior.
