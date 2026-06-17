# ringbuf_submit_after_discard_001

The program reserves a ringbuf record, writes a branch-derived mark, discards
the record on the IPv4 path, and then reaches a shared `bpf_ringbuf_submit()`.
On that path the verifier-tracked reference has already been consumed.

This is a reference lifecycle case. A correct repair must keep both behaviors:
IPv4 packets discard the marked record and drop, while non-IPv4 packets submit
the other marked record and pass.
