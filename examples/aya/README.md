# Aya

Use this when an Aya userspace loader rejects during `load()` or `attach()`.
The simplest integration is to keep your Rust loader unchanged and capture its
stderr/stdout:

```bash
RUST_LOG=debug cargo run --bin loader 2>&1 | tee verifier.log
bpfix verifier.log
```

`loader-snippet.rs` shows the intended error-handling shape: when load fails,
print the error with enough context, then let the wrapper or CI call BPFix on
the captured log.
