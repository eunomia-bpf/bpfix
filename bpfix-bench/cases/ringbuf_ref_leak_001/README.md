# ringbuf_ref_leak_001

Canary bucket: modern BPF reference lifecycle.

The program reserves ring-buffer memory, writes an event, and then has one
branch that returns before submitting or discarding the reserved record. The
verifier rejects the exit path:

```text
Unreleased reference id=...
BPF_EXIT instruction in main prog would lead to reference leak
```

A working repair must release the same reserved record on every path: discard it
on the early-return branch and submit it on the normal branch. The oracle checks
both successful helper paths in the verifier trace and then runs a packet test.
