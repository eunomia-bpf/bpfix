# ringbuf_double_submit_001

The program reserves a primary ringbuf record, writes packet metadata, submits
it, and then tries to emit an IPv4-only audit event by submitting the same
verifier-tracked record again.

This is a reference lifecycle / helper contract case. A correct repair must
not merely delete the second submit. It must preserve the primary event for all
full Ethernet frames and emit a second, distinct IPv4 audit ringbuf record marked
`99` while preserving IPv4 drop, non-IPv4 pass, and truncated-packet pass
behavior.
