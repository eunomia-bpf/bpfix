# Legacy Benchmark Tools

This directory no longer contains a Python implementation of BPFix. The active
diagnostic tool is the Rust workspace at the repository root.

Only legacy benchmark-maintenance tools remain here because `bpfix-bench`
metadata and reconstruction notes still reference them.

Generated Python artifacts are intentionally not kept here. Do not commit
`__pycache__/`, `.pytest_cache/`, `*.pyc`, coverage files, or other local
interpreter/test-run output.

Contents:

- `tools/validate_benchmark.py`: replay and validate `bpfix-bench` cases
- `tools/replay_case.py`: shared build/load/log parsing helper
- `tools/sync_external_raw_bench.py`: maintain raw external audit records
- `tools/integrate_reconstruction_batch.py`: apply reviewed reconstruction
  metadata

Use the Rust CLI for maintained development:

```bash
cargo run -p bpfix -- <verifier-log>
```

Use the current diagnostic evaluation script for product metrics:

```bash
python3 bpfix-bench/run-bpfix-eval.py --confusion
```
