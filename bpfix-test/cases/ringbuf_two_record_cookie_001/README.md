# ringbuf_two_record_cookie_001

Ringbuf provenance case with two reserved records. The first record carries a
constant audit mark, while the second carries branch-derived protocol state.
Correct repairs must remove the pointer-cookie round trip on the second record
and still preserve the audit submit, the branch-derived record write, and the
UDP/TCP return behavior. The verifier success log can summarize the UDP submit
path as `safe`, so the oracle checks two distinct submitted refs plus the
observable branch marks instead of claiming that every branch submit is printed.
