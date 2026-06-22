# BPFix-Test LLM Repair Evaluation

Date: 2026-06-22

This document writes the current `bpfix-test` result as an OSDI-style
evaluation section. It states the claims, baselines, workload, configurations,
oracles, results, and limitations for the LLM repair experiment. Every numeric
result below is backed by a completed `summary.json` result file listed in the
result-provenance table.

## Evaluation Question

Linux eBPF verifier logs expose the verifier's final rejection, but the final
line often does not explain the causal proof obligation that a repair must
preserve. BPFix produces a proof-aware diagnostic from the same failing program
and verifier output. The experiment asks:

> Does a BPFix diagnostic help an LLM generate a working eBPF source repair more
> often than the raw verifier log alone?

This is a repair experiment, not only a diagnostic-label experiment. A candidate
repair succeeds only if it is a complete replacement BPF C file that compiles,
loads through the verifier, and passes the executable case oracle.

## Claims

| Claim | Scope | Evidence in this document | Status |
| --- | --- | --- | --- |
| C1: Raw verifier logs are insufficient for hard one-shot eBPF repair. | `bpfix-test/splits/main.txt`, Qwen3.6 27B, temperature 0, one attempt. | Raw one-shot passes 22/75 cases. | Supported for the calibrated working suite. |
| C2: BPFix diagnostics improve LLM repair success over raw verifier logs. | Same cases, model, prompt budget, temperature, timeout, and oracle as C1. | BPFix one-shot passes 38/75, a +16 case / +21.4 percentage-point gain over raw. | Supported for Qwen3.6 27B. |
| C3: Retry helps both modes but does not erase the BPFix advantage. | Qwen3.6 27B, at most two attempts; retry prompt includes prior candidate and ordinary failure context. | Raw rises from 22/75 to 30/75; BPFix rises from 38/75 to 44/75. | Supported for Qwen3.6 27B. |
| C4: The benchmark is hard enough to distinguish model capacity from diagnostic signal. | Qwen2.5 3B capacity stress run, one attempt. | 3B raw passes 0/75; 3B+BPFix passes 8/75. | Supported as a stress baseline, not as a headline claim. |
| C5: The current suite is a calibrated working suite, not a clean heldout benchmark. | `main.txt` after hardening. | The split was edited during calibration; result metadata records dirty=false only after the calibration commit. | Supported; paper claims must not call this a heldout result. |

The strongest claim currently justified is narrow:

> On the calibrated 75-case `bpfix-test` working suite, under a fixed Qwen3.6
> 27B local configuration, BPFix plain-text diagnostics improve executable eBPF
> repair success over raw verifier logs by 16/75 cases in one shot and by 14/75
> cases with one retry.

The current evidence does not yet justify broad claims about all LLMs, all eBPF
verifier failures, or contamination-free benchmark generalization.

## Systems Compared

| System | Input to the model | Purpose | Disallowed input |
| --- | --- | --- | --- |
| Raw verifier log | `buggy.bpf.c` plus the case's raw `verifier.log`. | Baseline approximating what a developer or LLM sees from the kernel verifier. | BPFix diagnostic text, reference fix, oracle details, hidden predicates. |
| BPFix diagnostic | `buggy.bpf.c` plus the case's plain-text `diagnostic.txt`. | Tests whether BPFix's proof-aware diagnostic gives a better repair signal than raw logs. | Reference fix, oracle details, hidden predicates. |

Both modes use the same system prompt and require the model to output one full C
source file in a fenced `c` block. The model is never given `fixed.bpf.c`.

## Workload

The workload is `bpfix-test/splits/main.txt`.

| Field | Value | Why it is configured this way |
| --- | --- | --- |
| Split path | `bpfix-test/splits/main.txt` | This is the current 75-case combined working suite used for calibration and model comparison. |
| Expected count | `75` | The runner rejects accidental partial runs by requiring the split to contain exactly 75 cases. |
| Split SHA-256 | `fe1c7329c41c5a94d84ab6077539640082404d0cdef6bda0796440ec1e99d5a8` | Records the exact case list used for the run. |
| Case format | One directory per case with `buggy.bpf.c`, `verifier.log`, `diagnostic.txt`, `fixed.bpf.c`, and `test.py`. | Keeps each repair task source-first and independently executable. |
| Case admission rule | The buggy source must reproduce a verifier rejection; the checked-in fixed source must satisfy the same oracle. | Prevents non-reproducible or oracle-less cases from entering the denominator. |
| Suite status | Calibrated working suite, not heldout. | The suite was hardened to reach the target difficulty distribution; a paper-ready heldout must be frozen later. |

The suite includes synthetic proof-obligation cases and real-project inspired
cases from Cilium, bpftime, eunomia-bpf, xdp-tools, ActPlane, AgentSight,
Tetragon, tutorials, and related eBPF sources. The difficulty comes from
proof-lifecycle bugs, source/object correlation, modern BPF APIs, helper memory
contracts, and environment/configuration boundaries.

## Success Oracle

The oracle is the per-case `test.py`. A candidate is counted as a pass only if
all required checks pass.

| Oracle layer | What it checks | Why it is needed |
| --- | --- | --- |
| Source extraction | The model response contains a complete C source file. | Prevents prose-only or malformed responses from being counted. |
| Compile | `clang -target bpf -O2 -g -I /usr/include -D__TARGET_ARCH_x86 -c candidate.bpf.c`. | Ensures the candidate is a buildable BPF C program. |
| Verifier load | `bpftool -d prog load ... type <program-type>`. | Ensures the candidate satisfies the kernel verifier. |
| Functional tests | `bpftool prog run` packets, pinned maps, and map post-checks where applicable. | Prevents repairs that only satisfy the verifier by deleting behavior. |
| Verifier-success predicates | Required substrings or predicates over successful verifier logs. | Preserves proof shape for cases where functional return values are not enough. |
| Source-semantics predicates | Hidden `source_success_predicates` over the candidate source. | Blocks repairs that pass functional smoke tests by shrinking ABI, deleting copy windows, weakening helper protocols, or otherwise changing the source contract. |

Source-semantics predicates are reported under `source_semantics` in the oracle
JSON. The suite runner maps failed source-semantics checks to
`auxiliary_proof_predicate` in aggregate failure-stage reporting. Retry prompts
do not expose the predicate names or implementations.

## Run Configuration

All reported runs use the same runner:

```bash
python3 bpfix-test/tools/run_suite.py \
  --split bpfix-test/splits/main.txt \
  --expected-count 75 \
  --base-url <OpenAI-compatible endpoint> \
  --model <model name> \
  --model-path <local GGUF path when applicable> \
  --model-sha256 <GGUF sha256 when applicable> \
  --llama-cpp-dir <local llama.cpp path when applicable> \
  --timeout 900 \
  --max-tokens 8192 \
  --temperature 0 \
  --extra-body-json <provider-specific JSON object when required>
```

| Configuration | Value | Explanation |
| --- | --- | --- |
| API protocol | OpenAI-compatible chat completions. | `run_suite.py` appends `/chat/completions` to `--base-url`; llama.cpp uses a `/v1` base URL, while Z.ai uses `/api/coding/paas/v4`. |
| Temperature | `0` | Removes sampling as a controlled variable and makes the run as deterministic as the backend allows. |
| Max output tokens | `8192` | Large enough for full replacement C files, including verbose includes or helper definitions, while bounding runaway output. |
| Per-call timeout | `900` seconds | Allows long prompts and slow verifier-oriented generations without masking server hangs forever. |
| Attempts, one-shot | `--repair-attempts 1` by default | Tests whether the initial diagnostic is sufficient. |
| Attempts, retry | `--repair-attempts 2` | Tests a practical repair loop where the second prompt sees the previous candidate and ordinary compile/load/oracle failure context. |
| Retry context | Previous candidate source plus compile/load/verifier/oracle failure output. | Models a local developer retry loop while keeping raw and BPFix modes paired. |
| Retry exclusions | No hidden source predicate implementation and no `fixed.bpf.c`. | Prevents the retry from learning the answer from oracle internals. |
| Provider extra body | `--extra-body-json` when needed. | Records nonstandard but explicit provider settings, such as disabling GLM 5.2 deep thinking for direct source generation. |
| Result metadata | Git commit, dirty bit, split hash, toolchain versions, model path/hash, llama.cpp commit, prompt hash. | Makes each number auditable back to a run artifact. |

### Qwen3.6 27B Configuration

| Field | Value | Explanation |
| --- | --- | --- |
| Model | `Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf` | Primary strong local model used for benchmark calibration. |
| Model path | `/home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf` | Records the exact local artifact. |
| Model SHA-256 | `f7da7eee0f1ffa280742a293f02052d1f58d3253c9e109c1be8fb0067eb1b3a9` | Detects model-file drift. |
| llama.cpp commit | `57819b8d4b39d893408e51520dff3d47d1ebb757` | Pins the local inference backend. |
| llama.cpp server context | `-c 65536` | Fits the longest raw-log prompts while staying below the model's reported `n_ctx_train=262144`. |
| llama.cpp flags | `--host 127.0.0.1 --port 18080 --jinja --no-webui` | Binds the local OpenAI-compatible endpoint, uses the GGUF chat template, and disables the web UI. |

### Qwen2.5 3B Configuration

| Field | Value | Explanation |
| --- | --- | --- |
| Model | `qwen2.5-3b-instruct-q4_k_m.gguf` | Local small-model capacity stress baseline; this is the available local 3B Qwen GGUF. |
| Model path | `/home/yunwei37/workspace/llama.cpp-latest/models/qwen2.5-3b-instruct-q4_k_m.gguf` | Records the exact local artifact. |
| Model SHA-256 | `626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d` | Detects model-file drift. |
| Reported parameters | 3.40B | Captured by the llama.cpp `/v1/models` metadata. |
| Reported train context | `32768` tokens | Captured by the llama.cpp `/v1/models` metadata. |
| llama.cpp commit | `57819b8d4b39d893408e51520dff3d47d1ebb757` | Same local backend as the 27B run. |
| llama.cpp server context | `-c 32768` | Matches the model's reported train context; a larger `-c 65536` was not used for reported results. |
| llama.cpp flags | `--host 127.0.0.1 --port 18081 --jinja --no-webui` | Uses a separate local endpoint from the 27B runs and the model's GGUF chat template. |

The 3B run is one-shot only. It is included to test whether BPFix diagnostics
help a much smaller model at all; it is not used for the retry claim.

### GLM 5.2 Configuration

GLM 5.2 was run through the Z.ai OpenAI-compatible coding endpoint.

| Field | Value | Explanation |
| --- | --- | --- |
| Model | `glm-5.2` | Official Z.ai docs list this as the GLM 5.2 coding model code. |
| Endpoint | `https://api.z.ai/api/coding/paas/v4` | Official Z.ai docs list this as the OpenAI-compatible coding endpoint; the runner appends `/chat/completions`. |
| Endpoint check | Authenticated `/models` returned `glm-5.2` in the model list. | Confirms that the credential and endpoint selected the intended model family. |
| API key handling | Environment variable `ZAI_API_KEY`, passed via `--api-key-env ZAI_API_KEY`. | The runner records only the environment-variable name. The credential value is not printed, not written to result metadata, and not committed. |
| Extra request body | `{"thinking":{"type":"disabled"},"reasoning_effort":"none"}` | GLM 5.2 otherwise spends output budget on hidden `reasoning_content`; a minimal API check with `max_tokens=16` returned empty visible content under default thinking and visible `ok` with thinking disabled. |
| Why disable thinking | Match the benchmark contract: return one complete C source file under a fixed visible-output budget. | This keeps GLM from consuming the repair budget on hidden reasoning tokens and makes its outputs comparable to local direct-generation models. |
| One-shot provenance | Commit `d4440e5427143f294b9388db859a00f2f11119c6`, dirty=true. | These runs used the new `--extra-body-json` support before it was committed. |
| Retry provenance | Commit `560509fe7d9be6600e74482fd6962ec9bde5e2f0`, dirty=false. | The provider-extra-body runner support was committed before collecting retry runs. |

No API key value is printed or recorded in this document.

## Toolchain and Host Configuration

| Field | Value | Explanation |
| --- | --- | --- |
| Calibrated-suite commit | `f151473d945b0608709bc32505caf5f18becbe37` | Clean commit containing the calibrated suite and source-semantics predicates used by the 3B runs. Result directories are stored as local run artifacts rather than committed source files. |
| Provider-extra-body commit | `560509fe7d9be6600e74482fd6962ec9bde5e2f0` | Adds `--extra-body-json`, used for clean GLM 5.2 retry runs. |
| Dirty bit for reported 3B runs | `false` | Confirms the 3B runs were collected after the calibration commit. |
| Dirty bit for reported 27B runs | `true` in run metadata | The 27B calibration runs were collected before committing the final suite; the committed diff contains that calibration. |
| Dirty bit for GLM 5.2 one-shot runs | `true` in run metadata | The one-shot GLM runs were collected while `--extra-body-json` support was uncommitted. |
| Dirty bit for GLM 5.2 retry runs | `false` in run metadata | The retry GLM runs were collected after committing the provider-extra-body support. |
| Kernel | `Linux lab 6.15.11-061511-generic #202508201748 ... x86_64` | The verifier is kernel-dependent; this identifies the verifier used by the oracle. |
| Clang | `Ubuntu clang version 18.1.3` | BPF bytecode depends on compiler version. |
| bpftool/libbpf | `bpftool v7.7.0`, `libbpf v1.7` | Program load, verifier logs, and `prog run` behavior depend on these tools. |
| llvm-objdump | `Ubuntu LLVM version 18.1.3` | Recorded by the runner for replay/debug consistency. |
| GPU observed by llama.cpp | NVIDIA GeForce RTX 5090, 32 GB VRAM | Local inference throughput and feasible context are hardware-dependent. |

## Results

### Headline Result: Qwen3.6 27B

| Prompt mode | Attempts | Passed | Rate | Model errors | Gain over raw |
| --- | ---: | ---: | ---: | ---: | ---: |
| Raw verifier log | 1 | 22/75 | 29.3% | 0 | baseline |
| BPFix diagnostic | 1 | 38/75 | 50.7% | 0 | +16 cases / +21.4 pp |
| Raw verifier log | 2 | 30/75 | 40.0% | 0 | baseline |
| BPFix diagnostic | 2 | 44/75 | 58.7% | 0 | +14 cases / +18.7 pp |

Takeaway: BPFix substantially improves repair success for the primary calibrated
model. Retry helps both prompt modes, but the BPFix advantage remains after
retry.

### Hosted Result: GLM 5.2

| Prompt mode | Attempts | Passed | Rate | Model errors | Gain over raw |
| --- | ---: | ---: | ---: | ---: | ---: |
| Raw verifier log | 1 | 28/75 | 37.3% | 0 | baseline |
| BPFix diagnostic | 1 | 38/75 | 50.7% | 0 | +10 cases / +13.4 pp |
| Raw verifier log | 2 | 47/75 | 62.7% | 0 | baseline |
| BPFix diagnostic | 2 | 52/75 | 69.3% | 0 | +5 cases / +6.7 pp |

Takeaway: GLM 5.2 confirms a one-shot BPFix gain, but retry compresses the
diagnostic gap. The raw retry prompt recovers 18 cases and reaches 62.7%, so
the current retry loop is a strong intervention for this hosted model rather
than a small +10 point correction.

### Capacity Stress Result: Qwen2.5 3B

| Prompt mode | Attempts | Passed | Rate | Model-call failures | Gain over raw |
| --- | ---: | ---: | ---: | ---: | ---: |
| Raw verifier log | 1 | 0/75 | 0.0% | 3 | baseline |
| BPFix diagnostic | 1 | 8/75 | 10.7% | 0 | +8 cases / +10.7 pp |

The three raw-log model-call failures were HTTP 400 responses on the following
long raw prompts:

| Case | Prompt characters | Diagnostic/log characters |
| --- | ---: | ---: |
| `rs_actplane_cap_dynptr_payload_null_001` | 116163 | 113050 |
| `rs_eunomia_http_doff_copy_bound_001` | 74912 | 71112 |
| `rs_nccl_cpu_observer_slot_merge_001` | 67406 | 63212 |

These are counted as non-passes for the raw baseline. They also expose a
practical weakness of raw logs: long verifier traces can exceed or stress a
small model's usable context. The BPFix prompt for the same suite is shorter and
did not trigger model-call failures in the 3B run.

The 3B+BPFix pass cases were:

- `alu32_pointer_cookie_001`
- `packet_l4_branch_cookie_001`
- `rs_agentsight_process_ringbuf_null_001`
- `rs_cilium_srv6_segment_bound_001`
- `rs_nccl_cpu_observer_slot_merge_001`
- `rs_xdp_tools_ihl_macro_wrong_base_001`
- `rs_xdp_tools_xdpdump_perf_map_type_001`
- `subprog_map_value_null_001`

### Failure-Stage Breakdown

| Model | Mode | Attempts | Compile | Verifier load | Functional oracle | Auxiliary proof/source predicate | Model call |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3.6 27B | raw | 1 | 3 | 19 | 9 | 22 | 0 |
| Qwen3.6 27B | BPFix | 1 | 1 | 10 | 10 | 16 | 0 |
| Qwen3.6 27B | raw | 2 | 2 | 8 | 10 | 25 | 0 |
| Qwen3.6 27B | BPFix | 2 | 0 | 7 | 9 | 15 | 0 |
| GLM 5.2 | raw | 1 | 1 | 10 | 11 | 25 | 0 |
| GLM 5.2 | BPFix | 1 | 1 | 5 | 9 | 22 | 0 |
| GLM 5.2 | raw | 2 | 1 | 7 | 4 | 16 | 0 |
| GLM 5.2 | BPFix | 2 | 1 | 3 | 7 | 12 | 0 |
| Qwen2.5 3B | raw | 1 | 7 | 62 | 0 | 3 | 3 |
| Qwen2.5 3B | BPFix | 1 | 14 | 39 | 6 | 8 | 0 |

The 27B rows show that BPFix removes a meaningful number of verifier-load and
auxiliary proof failures, but not all failures. The remaining failures are often
semantic: candidates compile or load but fail functional or proof/source
contracts. That is the intended behavior of the stricter oracle.

The GLM 5.2 rows show that a hosted coding model can exploit retry context much
more aggressively than Qwen3.6 27B. BPFix still reduces verifier-load and
auxiliary proof failures, but the raw retry baseline becomes strong enough that
the retry gap shrinks to five cases.

The 3B rows show a different regime. The small model usually fails before
semantic repair quality becomes the main issue: raw outputs often fail verifier
load, and BPFix shifts some cases into compile/functional/proof failures while
rescuing eight cases.

## Result Provenance

| Label | Result file |
| --- | --- |
| Qwen3.6 27B raw one-shot | `bpfix-test/results/raw-main-qwen36-27b-hardened2-current/20260622T095443274429Z-pid2155539/raw/summary.json` |
| Qwen3.6 27B BPFix one-shot | `bpfix-test/results/bpfix-main-qwen36-27b-hardened2-current/20260622T101050360741Z-pid2167585/bpfix/summary.json` |
| Qwen3.6 27B raw retry | `bpfix-test/results/raw-main-qwen36-27b-hardened2-retry2-current/20260622T102327736469Z-pid2187731/raw/summary.json` |
| Qwen3.6 27B BPFix retry | `bpfix-test/results/bpfix-main-qwen36-27b-hardened2-retry2-current/20260622T105116447851Z-pid2222732/bpfix/summary.json` |
| GLM 5.2 raw one-shot | `bpfix-test/results/raw-main-glm52-thinking-disabled-current/20260622T211028217458Z-pid3229818/raw/summary.json` |
| GLM 5.2 BPFix one-shot | `bpfix-test/results/bpfix-main-glm52-thinking-disabled-current/20260622T211937511394Z-pid3244079/bpfix/summary.json` |
| GLM 5.2 raw retry | `bpfix-test/results/raw-main-glm52-thinking-disabled-retry2-current/20260622T212905484904Z-pid3277599/raw/summary.json` |
| GLM 5.2 BPFix retry | `bpfix-test/results/bpfix-main-glm52-thinking-disabled-retry2-current/20260622T214359370783Z-pid3313330/bpfix/summary.json` |
| Qwen2.5 3B raw one-shot | `bpfix-test/results/raw-main-qwen25-3b-current/20260622T204546033632Z-pid3194167/raw/summary.json` |
| Qwen2.5 3B BPFix one-shot | `bpfix-test/results/bpfix-main-qwen25-3b-current/20260622T204935041847Z-pid3198374/bpfix/summary.json` |

## Interpretation

BPFix helps because it changes the repair problem from "infer the missing proof
obligation from a verifier trace" to "apply a stated proof obligation to the
source while preserving behavior." The 27B raw baseline can solve 29.3% of the
calibrated suite in one shot, which means some verifier logs are already
sufficient for a strong model. The BPFix prompt raises that to 50.7%, showing
that the diagnostic adds useful signal on hard cases.

The retry result is important because it tests whether the BPFix gain is merely
a first-attempt artifact. It is not: raw retry recovers 8 more cases, BPFix retry
recovers 6 more cases, and BPFix remains ahead by 14 cases after both modes get
one failure-informed retry.

GLM 5.2 adds a caution. It agrees with the one-shot claim: BPFix improves
visible repair success from 28/75 to 38/75. However, retry changes the
distribution: raw rises to 47/75 and BPFix to 52/75. That means the current
retry prompt is powerful enough to solve many raw-log failures for this hosted
model, reducing diagnostic separation after retry. A paper should therefore
present one-shot and retry as different regimes, not as interchangeable
measurements of the same effect.

The 3B result is not intended to prove broad model generality. It shows two
useful stress facts. First, the suite is beyond the capacity of a small local
model in raw mode. Second, BPFix still rescues some cases and avoids the
small-context model-call failures triggered by very long raw logs.

## Publication Readiness

Using the OSDI evaluation rubric, this result is:

- Level 3 for the narrow claim that BPFix improves Qwen3.6 27B repair success on
  this calibrated working suite.
- Level 2 for any benchmark-quality or generalization claim, because the split
  was calibrated in place, the GLM one-shot runs are dirty-provenance runs, and
  retry compresses the hosted-model gap.

Before a paper can make final OSDI-level claims, the evaluation needs:

1. A frozen heldout split created after this calibration, with no post-result
   case hardening.
2. Clean reruns for every headline model/configuration, including GLM 5.2
   one-shot after committing provider-extra-body support.
3. A repetition or determinism policy. If temperature 0 is treated as
   deterministic, the paper must still state backend determinism assumptions.
4. An ablation that separates BPFix's proof-obligation content from mere
   shortening of raw logs.
5. A disaggregation by failure mechanism and source stratum.
6. A table of all failed cases and failure stages in the appendix.

For NeurIPS Evaluations & Datasets, the current state is not enough as a
standalone benchmark submission. That path would additionally require public
hosting, metadata, split construction rules, licensing/provenance tables,
documented intended use, limitations, and a broader model leaderboard.

## Threats to Validity

- The main split is not heldout. It is valid for calibration and internal
  comparison, but not for final generalization claims.
- The 27B run metadata is dirty because the run happened before committing the
  final calibrated state. The committed tree now contains the calibrated cases,
  but a final paper run should be collected from a clean commit.
- The GLM 5.2 one-shot metadata is dirty because the run happened before
  committing `--extra-body-json` support. The retry GLM runs are clean.
- The model matrix now includes one hosted model, one strong local model, and one
  small local model, but it is still too narrow for broad model-generalization
  claims.
- The benchmark uses executable oracles, which are stricter than text matching
  but still incomplete approximations of full production semantics.
- Source-semantics predicates reduce false positives but can introduce
  benchmark-specific assumptions. Each predicate should be audited and
  documented before freezing a heldout split.
- Raw prompts can be much longer than BPFix prompts. That is part of the
  practical baseline difference, but a pure information-content ablation should
  also compare against trimmed raw logs or summarized raw logs.

## Planned Next Runs

| Priority | Run | Decision gate |
| --- | --- | --- |
| Must | Freeze a new heldout split and rerun Qwen3.6 27B raw/BPFix one-shot and retry from a clean commit. | Confirms the headline result survives no-touch evaluation. |
| Must | Clean-rerun GLM 5.2 one-shot now that provider-extra-body support is committed. | Removes dirty-provenance caveat from the hosted-model one-shot result. |
| Should | Run a trimmed-raw baseline with the same model and prompt budget. | Separates BPFix proof signal from prompt-length reduction. |
| Should | Add one more strong open model. | Reduces model-specific risk. |
| Appendix | Run Qwen2.5 3B retry. | Shows whether small-model failures are recoverable or capacity-bound. |

## External References

- OSDI '26 Call for Papers: https://www.usenix.org/conference/osdi26/call-for-papers
- OSDI '26 Call for Artifacts: https://www.usenix.org/conference/osdi26/call-for-artifacts
- NeurIPS 2026 Evaluations & Datasets Call: https://neurips.cc/Conferences/2026/CallForEvaluationsDatasets
- NeurIPS 2026 Evaluations & Datasets Reviewer Guidelines: https://neurips.cc/Conferences/2026/EvaluationsDatasetsReviewerGuidelines
- Z.ai OpenAI-compatible coding endpoint documentation: https://docs.z.ai/devpack/tool/others
- Z.ai quick-start and GLM-5.2 model documentation: https://docs.z.ai/guides/overview/quick-start
- Z.ai deep-thinking parameter documentation: https://docs.z.ai/guides/capabilities/thinking
