# Artifact Reproduction

From a fresh checkout:

```bash
git submodule update --init --recursive && bash scripts/restore-empirical-fixtures.sh && make artifact-check
```

`artifact-check` runs `release-check`, audits the tracked BPFix-Bench result
summaries, and builds the paper arXiv package in Docker. The paper build writes
generated files inside the `paper` submodule; run it from a clean checkout if
you need a byte-for-byte clean worktree afterward. The restore step expands the
tracked empirical fixture archive into ignored replay logs used by
`release-check`.

## Tracked Inputs

- `crates/bpfix/` and `crates/bpfanalysis/`: implementation.
- `bpfix-empirical/manifest.yaml` and `bpfix-empirical/cases/`: 235 empirical
  verifier-rejection cases.
- `bpfix-bench/splits/main.txt` and `bpfix-bench/cases/`: frozen 75-case
  repair benchmark.
- `bpfix-bench/published-results/main75/`: compact `summary.json` files for the
  reported LLM repair runs. The full local `bpfix-bench/results/` tree is
  ignored because it contains generated candidates and large oracle logs.
- `paper/`: paper source submodule.

## Environment

- Rust/Cargo toolchain.
- Python 3.
- Docker for `make paper-arxiv`.

Full verifier replay additionally needs the pinned eBPF environment recorded in
the empirical corpus: Linux kernel `6.15.11`, Clang/LLVM 18, `bpftool`, BTF at
`/sys/kernel/btf/vmlinux`, libelf/zlib, and permission to load BPF programs.
Model-backed BPFix-Bench reruns need an OpenAI-compatible chat-completions
endpoint and the model settings recorded in
`docs/evaluation/bpfix-bench-llm-repair-eval.md`.

## Useful Commands

Release gate without rebuilding the paper:

```bash
make release-check
```

Audit the published BPFix-Bench summaries:

```bash
make bpfix-bench-published-results
```

Build the paper package:

```bash
make paper-arxiv
```

Full empirical replay on the pinned machine:

```bash
python3 bpfix-empirical/tools/validate_empirical.py --replay bpfix-empirical --timeout-sec 60
```

Audit the frozen benchmark split:

```bash
make bpfix-bench-main-gate
```

Model-backed benchmark rerun example:

```bash
python3 bpfix-bench/tools/run_suite.py \
  --split bpfix-bench/splits/main.txt \
  --expected-count 75 \
  --mode raw \
  --base-url http://127.0.0.1:18080/v1 \
  --model <model-name> \
  --timeout 900 \
  --max-tokens 8192 \
  --temperature 0
```

Use `--mode bpfix` for the BPFix-diagnostic condition, and
`--repair-attempts 2` for the one-retry condition. Use `--mode skills` to test
the checked-in `skills/ebpf-verifier-repair/` guidance with bounded failure
slices from raw verifier logs and no BPFix diagnostic input. The full raw logs
remain unchanged in each case directory:

```bash
python3 bpfix-bench/tools/run_suite.py \
  --split bpfix-bench/splits/main.txt \
  --expected-count 75 \
  --mode skills \
  --repair-attempts 2 \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M \
  --timeout 900 \
  --max-tokens 8192 \
  --temperature 0
```

## Expected Headline Counts

The implementation, BPFix-Bench split, checked-in benchmark fixtures, and local
result summaries agree for the headline BPFix-Bench claims in the paper:

- Qwen3.6 27B: raw one-shot 22/75, BPFix one-shot 38/75, raw retry 30/75,
  BPFix retry 44/75.
- GLM 5.2: raw one-shot 28/75, BPFix one-shot 38/75, raw retry 47/75,
  BPFix retry 52/75.
- Qwen2.5 3B: raw one-shot 0/75, BPFix one-shot 8/75, raw retry 0/75,
  BPFix retry 10/75.

The current active taxonomy in `bpfix-empirical/README.md` is:

```text
source_bug: 191
lowering_artifact: 18
environment_or_configuration: 14
verifier_false_positive: 7
verifier_limit: 5
```

Collapsing the two verifier-facing taxonomy labels gives the paper's
responsibility-layer breakdown: 191 developer, 18 compiler, 14 environment, and
12 verifier cases.
