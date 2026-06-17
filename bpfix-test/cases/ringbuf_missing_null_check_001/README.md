# ringbuf_missing_null_check_001

Canary bucket: modern BPF helper protocol / nullable proof.

The program reserves ring-buffer memory and immediately writes to the returned
pointer without checking whether `bpf_ringbuf_reserve()` returned null. The raw
verifier log rejects the write:

```text
R0 invalid mem access 'ringbuf_mem_or_null'
```

A working repair must check the nullable reserve result, write the event into
the non-null `ringbuf_mem`, and submit that same record. The oracle rejects
candidates that delete the ring-buffer operation, submit without writing, or
write one record and submit another.
