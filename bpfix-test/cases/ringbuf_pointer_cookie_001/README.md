# ringbuf_pointer_cookie_001

The program parses IPv4 traffic, reserves a ringbuf record, checks the nullable
helper result, then casts the `ringbuf_mem` pointer through an integer cookie
before writing and submitting the record.

The verifier rejects the shift on the live pointer:

```text
pointer arithmetic with <<= operator prohibited
```

A working repair must keep the ringbuf record as verifier-tracked
`ringbuf_mem`, write `mark = 7`, submit that same record, and preserve the UDP
drop / TCP pass behavior.
