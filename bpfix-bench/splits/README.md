# BPFix-Bench Splits

Current splits:

- `main.txt`: 75-case combined working suite. This is the default split for
  iterative LLM repair experiments.
- `main.manifest.json`: oracle metadata for `main.txt`, including custom
  oracle coverage for cases that do not use the common `run_case(...)` wrapper.
- `dev40.txt`: original 40-case admitted calibration split.
- `hard40.txt`: 40-case high-difficulty calibration subset retained from the
  main-suite hardening pass. It is useful for fast difficulty checks, but it is
  still calibration data rather than a clean heldout split.
- `real-seed-candidates.txt`: 34 real-project seed staging cases.
- `clean60.txt`: legacy empty heldout placeholder.

`main.txt` is intentionally allowed to include both calibration and staging
cases. It is useful for engineering iteration and multi-model comparison, but it
is not a contamination-free heldout benchmark.

Basic audit commands:

```bash
python3 bpfix-bench/tools/audit_cases.py --split bpfix-bench/splits/main.txt --manifest bpfix-bench/splits/main.manifest.json
python3 bpfix-bench/tools/run_suite.py --split bpfix-bench/splits/main.txt --expected-count 75 --mode bpfix --prompt-only
```

The older strict clean60 protocol and pilot notes live under
`docs/tmp/bpfix-bench/`.
