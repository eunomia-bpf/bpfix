# BPFix Project Status and Roadmap

Last updated: 2026-05-22

BPFix is scoped as a Rust userspace diagnostic tool for eBPF verifier failures.
The maintained product goal is: take existing verifier logs and return
Rust-style diagnostics that are stable enough for developers, CI systems, and
other tools to consume.

Repair synthesis, verifier-oracle patch loops, and paper-only experiments are
not part of the active product scope in this repository pass. Historical notes
under `docs/tmp/` are intentionally non-canonical. The previous Python
implementation has been removed; `docs/bpfix-py/` now contains only legacy
benchmark-maintenance tools.

## Current Thesis

The eBPF verifier already emits useful proof-attempt evidence in verbose logs:
per-instruction abstract register state, scalar bounds, pointer provenance,
offset/range facts, BTF source annotations, and backtracking notes. The last
verifier error line is often only the symptom. BPFix parses the trace and turns
that evidence into:

- a stable error ID
- a primary failure class
- the required verifier proof
- source or bytecode spans suitable for Rust-style diagnostics
- JSON output for downstream tooling

## Comparison With Rust Diagnostics

The useful comparison is Rust's diagnostic model, not Rust as a programming
language feature. Rust compiler errors work well because they are produced from
typed compiler facts: type inference, trait solving, borrow checking, spans,
secondary labels, notes, help text, and machine-readable diagnostic output. The
error message is not just the final failure string; it is an explanation of the
specific proof the compiler could not establish at a concrete source location.

BPFix applies the same diagnostic shape to eBPF verifier failures:

```text
rustc:
  source program
    -> compiler IR and typed analysis facts
    -> error id, primary span, secondary labels, notes, help

bpfix:
  verifier log + optional .o/BTF
    -> verifier states keyed by pc + object CFG/source sites
    -> required verifier proof, proof lifecycle, spans, notes, help
```

This is the intended "Rust-style" user experience: keep the existing eBPF
workflow, but replace a terminal verifier rejection with a structured
diagnostic that tells the developer what safety fact was needed, where it was
established, where it was lost or became insufficient, and which value reaches
the rejected instruction.

The boundary is also important. BPFix is not a replacement verifier, not a new
eBPF language, and not a promise of automatic repair. Unlike `rustc`, it runs
after the kernel verifier has already rejected the program, so it must recover
facts from the verbose verifier trace and optional object metadata. Log-only
mode must remain useful; `.o` and BTF should enrich localization and CFG
correlation when available.

The architectural consequence is:

- `bpfanalysis` stays a neutral analysis library for verifier logs, bytecode,
  CFGs, and low-level program facts.
- `bpfix` owns the product diagnostic layer: required proof, failure class,
  source labels, notes, help text, and JSON rendering.
- Evaluation should measure whether users can understand the missing verifier
  proof and relevant code region, not only whether a terminal error string was
  classified correctly.

## Active Capabilities

The active project is a Cargo workspace.

| area | status | canonical path |
| --- | --- | --- |
| Rust CLI | active | `crates/bpfix`, `cargo run -p bpfix -- ...` |
| verifier-log summary parser | active | `crates/bpfanalysis/src/verifier_log.rs` |
| CFG/lift/lower analysis | active | `crates/bpfanalysis/src/analysis/` |
| BPF instruction model | active | `crates/bpfanalysis/src/insn.rs` |
| pass context/support types | active | `crates/bpfanalysis/src/pass.rs` |
| libbpf source reference | active | `vendor/libbpf` submodule |
| benchmark corpus | active | `bpfix-bench/` |
| benchmark replay tools | legacy maintenance | `docs/bpfix-py/tools/` |

The `bpfanalysis` crate imports the analysis implementation from the `bpfopt`
analysis module and keeps the dependent instruction, verifier-log, and
pass-context modules needed to compile that analysis as a standalone library.

## Benchmark Snapshot

`bpfix-bench/manifest.yaml` is the primary benchmark discovery entry point.

Replayable cases: 235.

| source_kind | cases |
| --- | ---: |
| `github_issue` | 18 |
| `github_commit` | 46 |
| `kernel_selftest` | 85 |
| `stackoverflow` | 86 |

Primary taxonomy labels:

| taxonomy_class | cases |
| --- | ---: |
| `source_bug` | 187 |
| `lowering_artifact` | 24 |
| `environment_or_configuration` | 11 |
| `verifier_false_positive` | 9 |
| `verifier_limit` | 4 |

External raw audit records: 736.

| source_kind | records |
| --- | ---: |
| `github_commit` | 591 |
| `github_issue` | 31 |
| `stackoverflow` | 114 |

Current raw reproduction statuses:

| status | records |
| --- | ---: |
| `replay_valid` | 150 |
| `replay_reject_no_rejected_insn` | 4 |
| `attempted_accepted` | 32 |
| `environment_required` | 197 |
| `missing_source` | 31 |
| `missing_verifier_log` | 15 |
| `not_reconstructable_from_diff` | 45 |
| `out_of_scope_non_verifier` | 262 |

## Maintained Commands

Run the active Rust tests:

```bash
cargo test --workspace
```

Check the workspace:

```bash
cargo check --workspace
```

Quick diagnostic smoke:

```bash
cargo run -p bpfix -- bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log --format both
```

Legacy benchmark replay tools remain available for corpus maintenance:

```bash
python3 docs/bpfix-py/tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
python3 docs/evaluation/evaluate_diagnostics.py --confusion
```

Current Rust evaluation TODO:

- run `bpfix` over every admitted benchmark log in log-only mode
- rerun cases with available objects using `--object`
- report required-proof coverage by verifier proof family
- report source/bytecode localization coverage
- report object-CFG attachment success and non-fatal object-analysis failures
- report latency on the same machine and command configuration

## Near-Term Roadmap

1. Keep the project usable as an open-source Rust userspace tool: stable CLI,
   clear crate layout, and maintained docs.
2. Treat `bpfix-bench/manifest.yaml` and `bpfix-bench/raw/index.yaml` as the
   source of benchmark facts.
3. Expand `crates/bpfix` classification coverage from current benchmark gaps
   while keeping JSON output stable.
4. Expose more typed analysis from `bpfanalysis` instead of relying on final
   verifier-message matching.
5. Keep repair synthesis out of the active API until it is implemented,
   validated, and documented as a separate capability.

## Non-Goals For This Pass

- automatic patch generation
- semantic correctness oracle integration
- cross-kernel benchmark claims
- paper-number claims based on historical `docs/tmp/` reports
- treating raw records as primary benchmark cases before local replay admission

## Documentation Ownership

Canonical current facts live in:

- `README.md`
- `docs/research-plan.md`
- `docs/workshop-paper-plan.md`
- `docs/open-source-tool-design.md`
- `docs/evaluation/`
- `bpfix-bench/README.md`
- `bpfix-bench/manifest.yaml`
- `bpfix-bench/raw/index.yaml`

`docs/tmp/` is retained for historical analysis reports and should not be used
as the source of current project status.
