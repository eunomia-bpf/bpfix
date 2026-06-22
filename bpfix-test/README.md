# BPFix-Test

`bpfix-test/` is the source-first LLM repair stress suite for BPFix. It is not
`bpfix-bench/`: success here means a candidate replacement `buggy.bpf.c` builds,
loads through the verifier, and passes the case oracle.

Current case inventory:

- `cases/`: 77 directories on disk.
- runnable tracked fixtures: 75 with `buggy.bpf.c`, `verifier.log`,
  `diagnostic.txt`, and `test.py`.
- `splits/dev40.txt`: 40 admitted calibration cases.
- `splits/hard40.txt`: 40-case high-difficulty calibration subset retained
  from main-suite hardening.
- `splits/real-seed-candidates.txt`: 34 real-project seed staging cases.
- `splits/main.txt`: 75-case combined working suite: all runnable fixtures.
- `splits/main.manifest.json`: oracle metadata for the combined suite.
- `splits/clean60.txt`: legacy empty heldout placeholder, kept only so older
  scripts do not break.

The two non-runnable directories are placeholders without `buggy.bpf.c` and are
not part of any split.

## Case Format

Each case is a directory:

```text
cases/<case_id>/
  README.md
  buggy.bpf.c
  fixed.bpf.c
  verifier.log
  diagnostic.txt
  test.py
```

`buggy.bpf.c` is the source given to the model. `verifier.log` is the raw
verifier/load log. `diagnostic.txt` is BPFix plain-text output generated from
that same log. `fixed.bpf.c` is a checked-in reference repair that must pass the
same oracle. `test.py` is the only oracle for repair success.

## Main Commands

Audit the 40 admitted calibration cases:

```bash
python3 bpfix-test/tools/audit_cases.py --split bpfix-test/splits/dev40.txt
```

Audit the combined 75-case working suite:

```bash
python3 bpfix-test/tools/audit_cases.py --split bpfix-test/splits/main.txt --manifest bpfix-test/splits/main.manifest.json
```

Verify that all buggy sources still reject:

```bash
python3 bpfix-test/tools/run_suite.py --split bpfix-test/splits/main.txt --expected-count 75 --smoke
```

Verify checked-in repairs when a case has `fixed.bpf.c`:

```bash
python3 bpfix-test/tools/run_suite.py --split bpfix-test/splits/main.txt --expected-count 75 --fixed-smoke
```

Generate prompts without calling a model:

```bash
python3 bpfix-test/tools/run_suite.py \
  --split bpfix-test/splits/main.txt \
  --expected-count 75 \
  --mode bpfix \
  --prompt-only
```

Run an OpenAI-compatible model server, for example llama.cpp:

```bash
python3 bpfix-test/tools/run_suite.py \
  --split bpfix-test/splits/main.txt \
  --expected-count 75 \
  --mode raw \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M
```

Allow one repair retry without BPFix. The second prompt appends the previous
candidate source and the compile/load/verifier/oracle failure context:

```bash
python3 bpfix-test/tools/run_suite.py \
  --split bpfix-test/splits/main.txt \
  --expected-count 75 \
  --mode raw \
  --repair-attempts 2 \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M
```

Available modes are `source-only`, `raw`, `trimmed-raw`, and `bpfix`.

The current Qwen3.6 27B main75 calibration result is documented in
`docs/tmp/bpfix-test/qwen27b-main75-repair-results.md`: raw one-shot 22/75,
BPFix one-shot 38/75, raw retry 30/75, and BPFix retry 44/75.

Refresh diagnostics from existing logs without recapturing verifier output:

```bash
cargo build -p bpfix
python3 bpfix-test/tools/refresh_case_artifacts.py --diagnostic-only
```

Use full refresh only when the local kernel/toolchain/replay environment is
ready:

```bash
python3 bpfix-test/tools/refresh_case_artifacts.py
```

## How To Report Results

Report `main` as an evolving working suite, not as a clean heldout benchmark.
When reporting LLM repair results, separate one-shot from retry and separate
raw verifier-log prompts from BPFix-assisted prompts.
The remaining real-seed staging cases should be fixed and promoted only after
their diagnostics and oracles pass `audit_cases.py`.
If a paper later needs a frozen benchmark, freeze a new split from the current
suite, record the exact case ids and prompt hashes, and do not change that split
after model results are collected.
The calibrated `main` suite is useful for engineering and model comparison, but
it should not be described as a contamination-free heldout result.

The old dev40/clean60 design notes and pilot result writeups have been moved to
`docs/tmp/bpfix-test/`. They are useful historical context, but they are no
longer the primary user-facing benchmark contract.
