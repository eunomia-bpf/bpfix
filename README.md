# BPFix

BPFix is a userspace diagnostic tool for eBPF verifier failures. It turns verbose
verifier logs into Rust-style diagnostics: a stable error ID, a failure class,
the verifier obligation that was not proven, source or bytecode spans when they
are available, and repair-oriented hints.

BPFix does not patch the kernel and does not replace the verifier. It consumes
the verifier output that developers already get from `bpftool`, libbpf, Aya,
BCC, or project-specific loaders.

## Current Scope

Active scope:

- parse raw verifier logs, including LOG_LEVEL2 per-instruction state traces
- classify failures with a stable error catalog
- infer verifier proof obligations from bytecode and abstract state
- reconstruct proof/loss evidence with CFG, dataflow, slicing, and carrier
  lifecycle analysis
- render human-readable diagnostics and schema-valid JSON
- replay and evaluate the curated `bpfix-bench` verifier-failure corpus

Out of scope for the current tool:

- automatic source patch synthesis
- semantic correctness or runtime behavior validation
- kernel patches or verifier instrumentation
- paper-only experiments under `docs/tmp/`

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

For runtime dependencies without editable packaging metadata:

```bash
pip install -r requirements.txt
```

## CLI Usage

Generate a human-readable diagnostic from a verifier log:

```bash
python -m bpfix path/to/verifier.log
```

Generate JSON:

```bash
python -m bpfix path/to/verifier.log --format json
```

Print both:

```bash
python -m bpfix path/to/verifier.log --format both
```

The CLI can also read a raw benchmark YAML record and extract its embedded
verifier log:

```bash
python -m bpfix bpfix-bench/raw/so/stackoverflow-60053570.yaml --format both
```

Pipe a log over stdin:

```bash
cat verifier.log | python -m bpfix --format json
```

If you have `bpftool prog dump xlated linum` output, pass it to improve source
correlation:

```bash
python -m bpfix verifier.log --bpftool-xlated xlated-linum.txt
```

## Python API

```python
from pathlib import Path

from bpfix import build_diagnostic, generate_diagnostic

raw_log = Path("verifier.log").read_text()

schema_valid_payload = build_diagnostic(raw_log, case_id="demo-case")
rich_output = generate_diagnostic(raw_log)

print(rich_output.text)
print(schema_valid_payload["error_id"])
```

The structured output schema is [bpfix/schema/diagnostic.json](bpfix/schema/diagnostic.json).

The old `interface.*` import namespace is kept as a compatibility alias, but new
code should import from `bpfix.*`.

## Repository Layout

```text
bpfix/
  cli.py             Command-line interface
  api/               Public Python helpers
  extractor/         Parser, analysis pipeline, source correlation, renderer
  extractor/engine/  CFG, dataflow, slicing, monitor, opcode safety
  baseline/          Regex baseline used by evaluation
  catalogs/          Stable error and obligation catalogs
  schema/            JSON schema for diagnostic output
interface/
  __init__.py        Compatibility alias for old imports
bpfix-bench/
  manifest.yaml      Single entry point for replayable verifier-reject cases
  cases/             Self-contained local reproducers admitted to the benchmark
  raw/               External SO/GH/commit audit material
tools/
  validate_benchmark.py  Rebuild/load replay validator
  evaluate_benchmark.py  Fresh-replay diagnostic evaluation runner
  sync_external_raw_bench.py Raw external audit/index generator
tests/
  test_*.py          Unit, schema, CLI, parser, and evaluation smoke tests
docs/
  research-plan.md   Current project status and roadmap
  evaluation/        Benchmark and metric documentation
  tmp/               Historical working notes; not the source of current facts
```

## Current Benchmark Snapshot

`bpfix-bench/manifest.yaml` currently lists 235 replayable verifier-reject
cases:

| source kind | cases |
| --- | ---: |
| GitHub issue | 18 |
| GitHub commit | 46 |
| kernel selftest | 85 |
| Stack Overflow | 86 |
| **total** | **235** |

Current primary taxonomy labels:

| class | cases |
| --- | ---: |
| `source_bug` | 187 |
| `lowering_artifact` | 24 |
| `environment_or_configuration` | 11 |
| `verifier_false_positive` | 9 |
| `verifier_limit` | 4 |

## Development

Run the unit test suite:

```bash
python -m pytest tests/ -q
```

Inspect the CLI:

```bash
python -m bpfix --help
```

Replay the benchmark:

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

Full benchmark replay requires the pinned kernel/compiler/libbpf/BTF
environment. On this host, the latest full replay passed the 150 non-selftest
cases and failed the 85 kernel selftest cases at build time because `-lbpf` was
not available to the linker.

Run diagnostic evaluation on freshly replayed logs:

```bash
python3 tools/evaluate_benchmark.py --benchmark bpfix-bench --timeout-sec 60
```

`docs/tmp/` is intentionally not treated as canonical project state. Use
`README.md`, `docs/research-plan.md`, and `docs/evaluation/` for maintained
facts.
