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

## Product Use Cases

BPFix should be judged by whether it helps a developer decide what to try next,
not by whether it only improves a paper metric.

The main user-visible workflows are:

- local debugger: paste or pipe a `bpftool`, libbpf, Aya, BCC, or build log and
  get the rejected operation, required verifier proof, and concrete `help`
  guidance
- CI annotator: run BPFix on failed verifier logs and publish stable JSON as
  build annotations, review comments, or artifacts
- editor/agent backend: expose diagnostic spans, verifier evidence, and
  machine-readable failure classes to tools that can show or reason over them
- maintainer triage aid: distinguish source bugs from environment problems,
  lowering artifacts, verifier limits, and likely verifier false positives

The benchmark is supporting infrastructure for these workflows. It should catch
regressions, measure coverage, and supply examples, but it should not become
the only documented way to use the project.

## User-Ready Bar

A change moves BPFix toward an open-source tool when it improves at least one
of these surfaces:

- easier installation, build, or submodule setup
- accepting logs from real eBPF workflows without custom wrappers
- better localization of the rejected source or bytecode site
- clearer proof-oriented `help` messages
- stable JSON for CI, editors, and agents
- examples that users can run outside the benchmark harness

Pure evaluation work belongs in `docs/evaluation/` or `docs/tmp/` until it is
connected to one of those user-visible surfaces.

## Documentation Surfaces

- `README.md`: user-facing overview, quick start, examples, current status
- `docs/open-source-tool-design.md`: public CLI, JSON, and product boundaries
- `bpfix-bench/README.md`: replayable benchmark setup and validation
- `docs/research-plan.md`: roadmap and current implementation status
- `docs/workshop-paper-plan.md`: paper story, separated from product docs

## CLI Contract

Build from source:

```bash
cargo build --workspace
```

Install from this checkout:

```bash
cargo install --path crates/bpfix
```

Run on a verifier log:

```bash
bpfix verifier.log
```

Pipe a failing load command:

```bash
sudo bpftool -d prog load xdp.o /sys/fs/bpf/xdp 2>&1 | bpfix
```

Pass a full build or libbpf log. BPFix extracts the verifier region when it can:

```bash
bpfix build-or-load.log
```

Use optional object metadata. This path is explicit and feature-gated because
object analysis is an enhancement, not the default input contract:

```bash
cargo install --path crates/bpfix --features object-analysis
bpfix --object xdp.o verifier.log
```

Emit JSON:

```bash
bpfix --format json verifier.log
```

Emit both text and JSON:

```bash
bpfix --format both verifier.log
```

The public CLI model is:

```text
bpfix [OPTIONS] [LOG]
```

`LOG` is optional. When omitted or set to `-`, BPFix reads stdin. Positional
input and stdin are always verifier/build/load log text. BPFix does not run the
loader command in the default path, and the public contract should not include a
command-execution shortcut. Docker execution, if supported, must be an explicit
option such as `--docker`; benchmark YAML and repository workspace analysis also
stay outside the positional argument. Plain text is the default because the
common path is human debugging; JSON is opt-in for CI, editors, and agents.

## Input Policy

Required:

- verifier log text, either from a file or stdin

Optional:

- compiled BPF object via `--object` in a build with `object-analysis`
- source comments already present in the verifier log
- Docker/replay environment selection via an explicit `--docker`-style option,
  only if that mode is implemented

Evaluation-only:

- `bpfix-bench` YAML records and labels, consumed by evaluation scripts rather
  than the public default CLI

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
- `confidence`
- `diagnostic_kind`
- `help_safety`
- `span_confidence`
- `message`
- `required_proof`
- `source_span`
- `related_spans`
- `evidence`
- `help`
- `metadata`

The JSON field is `help` because BPFix explains what proof the verifier needs.
It does not synthesize source patches.

The formal schema is tracked at `docs/evaluation/diagnostic.schema.json`.

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
- Keep `docs/evaluation/diagnostic.schema.json` aligned with the Rust JSON
  renderer before external examples depend on it.
- Add golden text and JSON fixtures for representative proof families.
- Implement BTF-backed source correlation behind `object-analysis` without
  changing the log-only CLI shape.
- Publish examples for `bpftool`, libbpf/Aya logs, CI annotations, and editor
  integration.
