# BPFix-Test

`bpfix-test/` is the source-first LLM repair stress suite for BPFix. It is not
`bpfix-bench/`: success here means a candidate replacement `buggy.bpf.c` builds,
loads through the verifier, and passes the case oracle.

Current case inventory:

- `cases/`: 77 directories on disk.
- runnable tracked fixtures: 75 with `buggy.bpf.c`, `verifier.log`,
  `diagnostic.txt`, and `test.py`.
- `splits/dev40.txt`: 40 admitted calibration cases.
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
  verifier.log
  diagnostic.txt
  test.py
```

`buggy.bpf.c` is the source given to the model. `verifier.log` is the raw
verifier/load log. `diagnostic.txt` is BPFix plain-text output generated from
that same log. `test.py` is the only oracle for repair success.

## Main Commands

Audit the 40 admitted calibration cases:

```bash
python3 bpfix-test/tools/audit_cases.py --split bpfix-test/splits/dev40.txt
```

Audit the combined 75-case working suite:

```bash
python3 bpfix-test/tools/audit_cases.py --split bpfix-test/splits/main.txt --manifest bpfix-test/splits/main.manifest.json
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

Available modes are `source-only`, `raw`, `trimmed-raw`, and `bpfix`.

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
The remaining real-seed staging cases should be fixed and promoted only after
their diagnostics and oracles pass `audit_cases.py`.
If a paper later needs a frozen benchmark, freeze a new split from the current
suite, record the exact case ids and prompt hashes, and do not change that split
after model results are collected.

The old dev40/clean60 design notes and pilot result writeups have been moved to
`docs/tmp/bpfix-test/`. They are useful historical context, but they are no
longer the primary user-facing benchmark contract.
