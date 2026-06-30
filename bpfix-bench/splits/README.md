# BPFix-Bench Splits

Current splits:

- `main.txt`: frozen 75-case benchmark split. Use this as the default
  denominator for reported BPFix-Bench model comparisons.
- `main.manifest.json`: frozen split metadata and oracle coverage for
  `main.txt`, including custom oracle coverage for cases that do not use the
  common `run_case(...)` wrapper.
- `dev40.txt`: original 40-case development subset, retained only for
  provenance and quick compatibility checks.
- `hard40.txt`: 40-case high-difficulty development subset retained from
  benchmark hardening.
- `real-seed-candidates.txt`: historical provenance ledger for real-project
  seed cases used while constructing the released main75 suite.

`main.txt` is the public benchmark contract. Do not mutate the split, case
fixtures, verifier logs, diagnostics, or case oracles in place. If the benchmark
needs to grow or be recaptured for a different kernel/toolchain, create a new
versioned split and manifest.

Basic audit commands:

```bash
python3 bpfix-bench/tools/audit_cases.py --split bpfix-bench/splits/main.txt --manifest bpfix-bench/splits/main.manifest.json
python3 bpfix-bench/tools/run_suite.py --split bpfix-bench/splits/main.txt --expected-count 75 --mode bpfix --prompt-only
```
