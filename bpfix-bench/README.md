# BPFix-Bench

`bpfix-bench/` is the frozen source-first LLM repair benchmark for BPFix. It is
separate from `bpfix-empirical/`: success here means a candidate replacement
`buggy.bpf.c` builds, loads through the kernel verifier, and passes the case
oracle.

The public benchmark split is `splits/main.txt`. It contains 75 runnable repair
tasks and is frozen for reporting. Do not edit cases, oracles, verifier logs, or
the split order in place; new benchmark revisions should use a new split or
versioned directory.

Current inventory:

- `cases/`: 77 directories on disk.
- runnable benchmark fixtures: 75 with `buggy.bpf.c`, `verifier.log`,
  `diagnostic.txt`, `fixed.bpf.c`, and `test.py`.
- `splits/main.txt`: frozen 75-case benchmark split.
- `splits/main.manifest.json`: frozen split metadata and oracle coverage.
- `splits/dev40.txt` and `splits/hard40.txt`: historical development subsets.
- `splits/real-seed-candidates.txt`: historical provenance ledger for
  real-project seeds used while constructing the released main75 suite.

The two non-runnable directories are placeholders without `buggy.bpf.c`; they
are excluded from all reported benchmark splits.

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

## Quick Start

Audit the frozen 75-case benchmark:

```bash
python3 bpfix-bench/tools/audit_cases.py --split bpfix-bench/splits/main.txt --manifest bpfix-bench/splits/main.manifest.json
```

Verify that all buggy sources still reject:

```bash
python3 bpfix-bench/tools/run_suite.py --split bpfix-bench/splits/main.txt --expected-count 75 --smoke
```

Verify checked-in repairs when a case has `fixed.bpf.c`:

```bash
python3 bpfix-bench/tools/run_suite.py --split bpfix-bench/splits/main.txt --expected-count 75 --fixed-smoke
```

Generate prompts without calling a model:

```bash
python3 bpfix-bench/tools/run_suite.py \
  --split bpfix-bench/splits/main.txt \
  --expected-count 75 \
  --mode bpfix \
  --prompt-only
```

Run an OpenAI-compatible model server, for example llama.cpp:

```bash
python3 bpfix-bench/tools/run_suite.py \
  --split bpfix-bench/splits/main.txt \
  --expected-count 75 \
  --mode raw \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M
```

Allow one repair retry without BPFix. The second prompt appends the previous
candidate source and the compile/load/verifier/oracle failure context:

```bash
python3 bpfix-bench/tools/run_suite.py \
  --split bpfix-bench/splits/main.txt \
  --expected-count 75 \
  --mode raw \
  --repair-attempts 2 \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M
```

Available modes are `source-only`, `raw`, `trimmed-raw`, and `bpfix`.

The published main75 results are documented in
`docs/evaluation/bpfix-bench-llm-repair-eval.md`. The headline Qwen3.6 27B
comparison is raw one-shot 22/75 versus BPFix one-shot 38/75, and raw retry
30/75 versus BPFix retry 44/75.

## Regenerating Artifacts

Refresh diagnostics from existing logs without recapturing verifier output:

```bash
cargo build -p bpfix
python3 bpfix-bench/tools/refresh_case_artifacts.py --diagnostic-only
```

Use full refresh only when the local kernel/toolchain/replay environment is
ready. For the frozen benchmark, write refreshed artifacts to a new versioned
split instead of mutating `splits/main.txt` in place:

```bash
python3 bpfix-bench/tools/refresh_case_artifacts.py
```

## How To Report Results

Use `splits/main.txt` as the benchmark denominator and report the exact prompt
mode, model, attempt count, split SHA-256, kernel, clang, bpftool/libbpf
versions, and result `summary.json` path. Separate one-shot from retry and
separate raw verifier-log prompts from BPFix-assisted prompts.

`main75` is a curated verifier-repair benchmark, not a natural-frequency sample
of all eBPF failures. Claims should therefore be scoped to source-level repair
tasks represented by the suite: packet/map proof lifecycle, helper memory
contracts, ring-buffer/dynptr protocols, source/object correlation, and
program/map environment constraints.

Historical development subsets are retained for provenance only. The
user-facing benchmark contract is this README, `splits/main.txt`,
`splits/main.manifest.json`, the case directories, and
`docs/evaluation/bpfix-bench-llm-repair-eval.md`.
