# BPFix Python Archive

This directory contains the previous Python implementation of BPFix. It is kept
as historical reference material while the active project entry point is the
Rust workspace at the repository root. It is not part of the maintained test or
release surface.

Contents:

- `bpfix/`: archived Python package
- `interface/`: old compatibility namespace
- `tests/`: archived Python test suite
- `tools/`: archived replay/evaluation helpers
- `pyproject.toml`: original Python packaging metadata

Use the Rust CLI for maintained development:

```bash
cargo run -p bpfix -- <verifier-log-or-raw-yaml>
```
