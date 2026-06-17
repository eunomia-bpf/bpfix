# ringbuf_double_submit_001

The program reserves a ringbuf record, writes a mark, submits it, and then
submits the same verifier-tracked record again on the IPv4 path.

This is a reference lifecycle / helper contract case. A correct repair must
submit the record exactly once, keep the ringbuf side effect, and preserve IPv4
drop, non-IPv4 pass, and truncated-packet pass behavior.
