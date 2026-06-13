# libbpf-rs

Most libbpf-rs applications already route libbpf diagnostics through stderr or
the application's logger. Keep that path and wrap the loader command:

```bash
./examples/libbpf-rs/run-and-diagnose.sh ./target/debug/loader xdp.o
```

The wrapper is intentionally small:

```bash
./target/debug/loader 2>&1 | tee verifier.log
bpfix --object xdp.o verifier.log
```

If your loader can expose libbpf's verifier buffer directly, write that buffer
to `verifier.log` and call the same `bpfix` command. BPFix does not need the
Rust project checkout; it only needs the log and, optionally, the `.o`.
