# Qwen 27B main75 Repair Results

Date: 2026-06-22

Suite: `bpfix-bench/splits/main.txt`, 75 cases.

Status: calibrated working-suite result. This is the current engineering
calibration for difficulty and BPFix-vs-raw separation. It is not a clean
heldout benchmark because `main.txt` is allowed to evolve during case hardening.

## Setup

Model server:

```bash
/home/yunwei37/workspace/llama.cpp-latest/build/bin/llama-server \
  -m /home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf \
  -c 65536 \
  --port 18080 \
  --host 127.0.0.1 \
  --jinja \
  --no-webui
```

Runner settings:

- model: `Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf`
- model sha256: `f7da7eee0f1ffa280742a293f02052d1f58d3253c9e109c1be8fb0067eb1b3a9`
- llama.cpp commit: `57819b8d4b39d893408e51520dff3d47d1ebb757`
- split sha256: `fe1c7329c41c5a94d84ab6077539640082404d0cdef6bda0796440ec1e99d5a8`
- temperature: `0`
- max tokens: `8192`
- timeout: `900`
- kernel: `Linux lab 6.15.11-061511-generic`
- clang: `Ubuntu clang version 18.1.3`
- bpftool/libbpf: `bpftool v7.7.0`, `libbpf v1.7`

Example runner command:

```bash
python3 bpfix-bench/tools/run_suite.py \
  --mode raw \
  --split bpfix-bench/splits/main.txt \
  --expected-count 75 \
  --results-dir bpfix-bench/results/raw-main-qwen36-27b-hardened2-current \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf \
  --model-path /home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf \
  --model-sha256 f7da7eee0f1ffa280742a293f02052d1f58d3253c9e109c1be8fb0067eb1b3a9 \
  --llama-cpp-dir /home/yunwei37/workspace/llama.cpp-latest \
  --timeout 900 \
  --max-tokens 8192 \
  --temperature 0
```

Use `--mode bpfix` for BPFix-assisted prompts. Add `--repair-attempts 2` for
the retry runs.

## Current Results

| Prompt mode | Attempts | Passed | Rate | Model errors | Retry gain |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw verifier log | 1 | 22/75 | 29.3% | 0 | - |
| raw verifier log | 2 | 30/75 | 40.0% | 0 | +8 cases / +10.7 pp |
| BPFix plain text | 1 | 38/75 | 50.7% | 0 | - |
| BPFix plain text | 2 | 44/75 | 58.7% | 0 | +6 cases / +8.0 pp |

Main deltas:

- BPFix one-shot improves over raw one-shot by 16 cases, or +21.4 percentage
  points.
- BPFix with one retry improves over raw with one retry by 14 cases, or +18.7
  percentage points.
- The calibrated distribution now matches the target shape: raw one-shot is
  around 20-30%, BPFix one-shot is around 50-60%, and retry provides an
  additional 8-11 percentage points.
- BPFix one-shot is not a strict superset of raw one-shot:
  `rs_eunomia_wq_container_map_001` passes raw but not BPFix in this run.

Result files:

- raw one-shot:
  `bpfix-bench/results/raw-main-qwen36-27b-hardened2-current/20260622T095443274429Z-pid2155539/raw/summary.json`
- BPFix one-shot:
  `bpfix-bench/results/bpfix-main-qwen36-27b-hardened2-current/20260622T101050360741Z-pid2167585/bpfix/summary.json`
- raw retry:
  `bpfix-bench/results/raw-main-qwen36-27b-hardened2-retry2-current/20260622T102327736469Z-pid2187731/raw/summary.json`
- BPFix retry:
  `bpfix-bench/results/bpfix-main-qwen36-27b-hardened2-retry2-current/20260622T105116447851Z-pid2222732/bpfix/summary.json`

## Failure Breakdown

| Prompt mode | Attempts | Compile | Verifier load | Functional oracle | Auxiliary proof/source predicate |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw verifier log | 1 | 3 | 19 | 9 | 22 |
| raw verifier log | 2 | 2 | 8 | 10 | 25 |
| BPFix plain text | 1 | 1 | 10 | 10 | 16 |
| BPFix plain text | 2 | 0 | 7 | 9 | 15 |

The retry breakdown describes the final failure stage after at most two
attempts. A higher auxiliary count after retry is not necessarily worse: several
second attempts move past compile/verifier rejection and are then rejected by
the stricter proof or source-semantics oracle.

## Oracle Semantics

Repair success requires all of the following:

1. Candidate source compiles as BPF C.
2. The program loads through the verifier.
3. Functional `bpftool prog run` checks pass.
4. Verifier-success predicates pass when the case requires proof-shape checks.
5. Source-semantics predicates pass when the case must preserve a hidden source
   contract that is not reliably observable from functional return values alone.

`bpfix-bench/tools/bpf_case.py` now supports `source_success_predicates`. These
checks are emitted under `source_semantics` in the oracle report. The suite
runner maps failed source-semantics checks to `auxiliary_proof_predicate` for
result summaries.

Retry prompts include the previous candidate and ordinary failure context, but
they do not expose the hidden source predicate names or implementation details.

## Hardening Since the Earlier 2026-06-19 Run

The earlier 75-case run was too easy: raw one-shot passed 48/75 and BPFix
one-shot passed 66/75. The current pass rates are lower because cases that raw
could solve by deleting semantics, shrinking buffers, weakening copy windows, or
using verifier-only local fixes were hardened with stronger oracles.

Representative hidden source predicates:

- `rs_bpftime_sslsniff_perf_copy_len_001`: preserve the 16-byte SSL capture ABI
  instead of shrinking `DATA_BUF_SIZE` or clamping the copy to a smaller local
  constant.
- `rs_eunomia_http_doff_copy_bound_001`: prove the TCP data-offset-derived byte
  length before using the HTTP capture copy window.
- `rs_cilium_proxy_skc_assign_ref_leak_001`: release the socket reference on all
  return paths after `bpf_sk_assign`.
- `rs_cilium_srv6_segment_bound_001`: bound the SRH plus first SID window before
  dereferencing SRH fields.
- `rs_cilium_mcast_igmpv3_grec_bound_001`: prove the IGMPv3 group-record byte
  window, not only a scalar loop condition.
- `rs_cilium_ipv6_exthdr_l4_offset_001`: keep the direct L4-to-UDP proof chain
  with a `(void *)(udp + 1)` packet bound.

## Publication Readiness

This result is strong enough as a calibration point for BPFix's evaluation
design, but not sufficient by itself as a final OSDI or NeurIPS benchmark claim.

Supported claim:

- Under one fixed local configuration, Qwen3.6 27B repairs the calibrated
  75-case working suite substantially more often with BPFix diagnostics than
  with raw verifier logs.

Not yet supported:

- Generalization across model families.
- Stability across repeated runs, seeds, temperatures, or server versions.
- A contamination-free heldout result, because `main.txt` was edited during
  calibration.
- A standalone benchmark contribution suitable for NeurIPS Evaluations &
  Datasets without dataset hosting, metadata, split policy, model matrix, and
  broader statistical reporting.

Required next steps before paper-level claims:

1. Freeze a new heldout split after this calibration and stop modifying it.
2. Run at least three model families, including one commercial frontier model,
   one strong open model, and one smaller open baseline.
3. Repeat the fixed-temperature configuration enough times to report variance
   or justify determinism.
4. Publish a case taxonomy, provenance table, split construction rule, and
   oracle audit.
5. Report exact prompts, prompt hashes, model versions, toolchain versions, and
   all failed cases.

Using the local OSDI evaluation rubric, the current result is Level 2
technical-report evidence for the benchmark and partial Level 3 evidence for
the narrow one-model claim. To reach a Level 4 systems narrative, the paper
needs frozen claims, named baselines, ablations, and the stress case most likely
to falsify the BPFix story.

Relevant conference guidance:

- OSDI '26 CFP emphasizes quantified or insightful systems results, practicality,
  correctness, and clear contribution boundaries:
  https://www.usenix.org/conference/osdi26/call-for-papers
- OSDI '26 artifact guidance expects artifacts to be consistent with the paper,
  complete, documented, reusable, and accompanied by instructions to replicate
  paper results:
  https://www.usenix.org/conference/osdi26/call-for-artifacts
- NeurIPS 2026 Evaluations & Datasets requires benchmark/data/code submissions
  to be hosted, accessible, clearly documented, and explicit about the
  evaluative claims, assumptions, and limitations they support:
  https://neurips.cc/Conferences/2026/CallForEvaluationsDatasets
- NeurIPS 2026 E&D reviewer guidance emphasizes responsible data practices,
  transparency, reproducibility, metadata completeness, dataset accessibility,
  and executable artifact documentation:
  https://neurips.cc/Conferences/2026/EvaluationsDatasetsReviewerGuidelines
