# BPFix

BPFix stands for Obligation-Oriented Diagnostics for eBPF Verifier Failures. The project treats verifier feedback as a systems interface problem: instead of relying on unstable free-text logs, it aims to build a stable, structured diagnostic layer that exposes what proof obligation failed, where it failed, and what kind of repair is appropriate.

The repository contains the current extractor pipeline, taxonomy/catalog data, and the unified `bpfix-bench` corpus used to analyze verifier failures.

## Install

Create a virtual environment and install BPFix in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

If you only want the raw dependencies without packaging metadata, `pip install -r requirements.txt` still works.

## Repository Layout

```text
bpfix-bench/
  manifest.yaml      Single entry point for replayable verifier-reject cases
  taxonomy.yaml      Five-class benchmark failure taxonomy
  cases/             Self-contained local reproducers admitted to the benchmark
  raw/               Collected SO/GH/commit material, including unreproduced records
interface/catalogs/
  error_catalog.yaml Stable verifier error catalog
  obligation_catalog.yaml Repair-oriented obligation templates
interface/extractor/
  pipeline.py        End-to-end diagnostic pipeline
  engine/            CFG, dataflow, slicing, opcode safety, and monitor logic
  trace_parser.py    LOG_LEVEL2 trace parser
interface/baseline/
  regex_diagnostic.py Regex baseline used by benchmark evaluation
interface/schema/
  diagnostic.json    Structured diagnostic output schema
tools/
  validate_benchmark.py  Replay validator for `bpfix-bench`
  evaluate_benchmark.py  Fresh-replay diagnostic baseline/ablation runner
  sync_external_raw_bench.py Raw external audit/index generator
tests/
  test_*.py          Extractor, renderer, schema, and CLI coverage
docs/
  research-plan.md   Longer-lived project notes
  tmp/               Ephemeral review and experiment reports
```

## CLI Usage

Generate a human-readable diagnostic from a raw verifier log:

```bash
python -m bpfix path/to/verifier.log
```

Generate JSON instead:

```bash
python -m bpfix path/to/verifier.log --format json
```

The CLI also accepts a raw benchmark YAML record and extracts its verifier log automatically:

```bash
python -m bpfix bpfix-bench/raw/so/stackoverflow-60053570.yaml --format both
```

You can also pipe a log over stdin:

```bash
cat verifier.log | python -m bpfix --format json
```

## Python Usage

```python
from pathlib import Path

from bpfix import build_diagnostic, generate_diagnostic

raw_log = Path("verifier.log").read_text()

schema_valid_payload = build_diagnostic(raw_log, case_id="demo-case")
rich_output = generate_diagnostic(raw_log)
print(rich_output.text)
```

The JSON schema for emitted diagnostics lives in [diagnostic.json](/home/yunwei37/workspace/ebpf-verifier-agent/interface/schema/diagnostic.json).

## Quick Start

Run the test suite:

```bash
python -m pytest tests/ -q
```

Inspect the CLI:

```bash
python -m bpfix --help
```

Replay the benchmark validator:

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

Run the diagnostic evaluation on freshly replayed verifier logs:

```bash
python3 tools/evaluate_benchmark.py --benchmark bpfix-bench --timeout-sec 60
```

## Project Scope

The current focus is the Python-based diagnostic/extraction pipeline plus the unified replayable benchmark. `docs/tmp/` is intentionally reserved for temporary reports rather than permanent documentation.
