# BPFix Project Status and Roadmap

Last updated: 2026-05-22

BPFix is currently scoped as a userspace diagnostic tool for eBPF verifier
failures. The maintained product goal is: take existing verifier logs and return
Rust-style diagnostics that are stable enough for developers, CI systems, and
other tools to consume.

Repair synthesis, verifier-oracle patch loops, and paper-only experiments are
not part of the active product scope in this repository pass. Historical notes
under `docs/tmp/` are intentionally non-canonical.

## Current Thesis

The eBPF verifier already emits useful proof-attempt evidence in verbose logs:
per-instruction abstract register state, scalar bounds, pointer provenance,
offset/range facts, BTF source annotations, and backtracking notes. The last
verifier error line is often only the symptom. BPFix parses the full trace and
turns that evidence into:

- a stable error ID
- a primary failure class
- the missing verifier proof obligation
- proof establishment/loss evidence when present
- source or bytecode spans suitable for Rust-style diagnostics
- JSON output for downstream tooling

## Active Capabilities

Code lives under the `bpfix/` package.

| area | status | canonical path |
| --- | --- | --- |
| CLI | active | `bpfix/cli.py`, `python -m bpfix` |
| Python API | active | `bpfix/api/__init__.py` |
| diagnostic pipeline | active | `bpfix/extractor/pipeline.py` |
| LOG_LEVEL2 trace parsing | active | `bpfix/extractor/trace_parser.py` |
| source correlation | active | `bpfix/extractor/source_correlator.py` |
| Rust-style renderer | active | `bpfix/extractor/renderer.py` |
| CFG/dataflow/slicing | active | `bpfix/extractor/engine/` |
| proof-carrier lifecycle analysis | active | `bpfix/extractor/engine/monitor.py` |
| opcode/safety-schema inference | active | `bpfix/extractor/engine/opcode_safety.py` |
| stable error catalog | active | `bpfix/catalogs/error_catalog.yaml` |
| obligation catalog | active | `bpfix/catalogs/obligation_catalog.yaml` |
| structured schema | active | `bpfix/schema/diagnostic.json` |
| regex baseline | active | `bpfix/baseline/` |
| replay validator | active | `tools/validate_benchmark.py` |
| diagnostic evaluation | active | `tools/evaluate_benchmark.py` |

The old `interface.*` namespace is kept only as a compatibility alias. New code
should import from `bpfix.*`.

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

## Maintained Evaluation Commands

Unit tests:

```bash
python -m pytest tests/ -q
```

Replay all admitted benchmark cases:

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

Latest local result on this checkout:

```text
passed: 150
failed: 85
total_cases: 235
```

All failures were `kernel_selftest` cases whose build failed because the host
linker could not find `-lbpf`. Stack Overflow, GitHub issue, and GitHub commit
cases replayed successfully locally.

Run diagnostic evaluation on freshly replayed logs:

```bash
python3 tools/evaluate_benchmark.py --benchmark bpfix-bench --timeout-sec 60
```

Quick diagnostic smoke:

```bash
python3 tools/evaluate_benchmark.py \
  --benchmark bpfix-bench \
  --limit 5 \
  --methods bpfix,baseline \
  --results-path /tmp/bpfix-eval-smoke.json \
  --timeout-sec 30
```

## Near-Term Roadmap

1. Keep the project usable as an open-source userspace tool: stable CLI,
   stable Python API, clear package layout, and maintained docs.
2. Treat `bpfix-bench/manifest.yaml` and `bpfix-bench/raw/index.yaml` as the
   source of benchmark facts.
3. Improve diagnostic quality on the 235 replayable cases before expanding
   product scope.
4. Keep taxonomy labels mutually exclusive and preserve secondary mechanisms as
   label metadata rather than new primary classes.
5. Improve source correlation and proof-event precision for trace-rich logs.
6. Keep repair synthesis out of the active API until it is implemented,
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
- `docs/evaluation/`
- `bpfix-bench/README.md`
- `bpfix-bench/manifest.yaml`
- `bpfix-bench/raw/index.yaml`

`docs/tmp/` is retained for historical analysis reports and should not be used
as the source of current project status.
