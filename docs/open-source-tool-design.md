# Open-Source Tool Design

This document defines the intended public tool shape for BPFix.

## User Model

BPFix should fit into an existing eBPF workflow. A developer should not need to
change loaders, rewrite source code, or run a patched kernel.

Primary users:

- kernel/eBPF developers debugging verifier rejections locally
- CI systems that want structured failure annotations
- editor or agent integrations that need machine-readable verifier diagnostics
- benchmark/evaluation scripts using `bpfix-bench`

## CLI Contract

Build from source:

```bash
cargo build --workspace
```

Run on a verifier log:

```bash
cargo run -p bpfix -- verifier.log
```

Pipe a failing load command:

```bash
sudo bpftool prog load xdp.o /sys/fs/bpf/xdp 2>&1 | cargo run -p bpfix --
```

Pass a full build or libbpf log. BPFix extracts the verifier region when it can:

```bash
cargo run -p bpfix -- build-or-load.log
```

Use optional object metadata:

```bash
cargo run -p bpfix -- --object xdp.o verifier.log
```

Emit JSON:

```bash
cargo run -p bpfix -- verifier.log --format json
```

Emit both text and JSON:

```bash
cargo run -p bpfix -- verifier.log --format both
```

Benchmark YAML is an evaluation convenience only:

```bash
cargo run -p bpfix -- bpfix-bench/raw/so/stackoverflow-60053570.yaml
```

Runtime diagnostics must not consume benchmark labels as input.

## Input Policy

Required:

- verifier log text, either from a file or stdin

Optional:

- compiled BPF object via `--object`
- source comments already present in the verifier log
- `bpfix-bench` YAML wrapper when evaluating bundled cases

Not required:

- source repository checkout
- kernel patch
- replay environment
- benchmark case metadata

## Output Policy

Text output is Rust-style and human-readable:

- stable `BPFIX-*` error ID
- failure class
- primary rejected span
- related proof lifecycle spans when available
- verifier evidence notes
- required proof
- `help:` guidance

JSON output is for tools. Version `bpfix.diagnostic/v2` contains:

- `diagnostic_version`
- `error_id`
- `failure_class`
- `message`
- `required_proof`
- `source_span`
- `related_spans`
- `evidence`
- `help`
- `metadata`

The JSON field is `help` because BPFix explains what proof the verifier needs.
It does not synthesize source patches.

## Product Boundaries

BPFix is:

- a userspace verifier-log diagnostic tool
- a structured JSON producer for CI/editor/agent integrations
- a benchmarked diagnostic engine for verifier proof failures

BPFix is not:

- an automatic patch generator
- a verifier replacement
- a semantic correctness checker
- a source-to-source transformation tool
- a kernel-side API change

## Near-Term Hardening

- Keep `cargo test --workspace` passing.
- Freeze the JSON v2 field names before external examples depend on them.
- Add golden text and JSON fixtures for representative proof families.
- Implement BTF-backed source correlation from `--object` without changing the
  log-only CLI shape.
- Publish examples for `bpftool`, libbpf/Aya logs, CI annotations, and editor
  integration.
