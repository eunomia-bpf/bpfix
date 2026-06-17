# ringbuf_nested_reserve_leak_001

The program reserves an audit ringbuf record and then reserves a second event
record. If the second reserve fails, it returns without submitting or
discarding the first record.

This is a reference lifecycle case. A correct repair must release the first
record on the second-reserve failure path and preserve the normal path that
submits two distinct records.
