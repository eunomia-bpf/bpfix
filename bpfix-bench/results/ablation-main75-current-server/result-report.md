# Main-75 repair-signal ablation result

## Question and tested mechanism

This experiment asks whether BPFix's one-shot repair gain comes only from a shorter prompt, from proof-aware diagnostic content, or from the rendered `help:` repair instructions.

The four conditions are:

- `source-only`: buggy source with no verifier evidence.
- `matched-raw-tail`: buggy source plus the largest complete-line suffix of the latest raw verifier load region that does not exceed the corresponding `bpfix-no-help` input-token budget.
- `bpfix-no-help`: the BPFix diagnostic with lines beginning with `help:` removed.
- `bpfix-neutral`: the full BPFix diagnostic. It uses the same neutral evidence label as the other diagnostic conditions.

The primary comparisons are `matched-raw-tail` versus `bpfix-no-help` and `bpfix-no-help` versus `bpfix-neutral`.

## Fixed setup

- Split: `bpfix-bench/splits/main.txt`, 75 cases, SHA-256 `fe1c7329c41c5a94d84ab6077539640082404d0cdef6bda0796440ec1e99d5a8`
- Repository commit: `89f54847097dbf5e205e06bbaeb4e3965df7871e`
- Model: `Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M`, SHA-256 `f7da7eee0f1ffa280742a293f02052d1f58d3253c9e109c1be8fb0067eb1b3a9`
- llama.cpp commit: `2d973636e292ee6f75fadcf08d29cb33511f509f`
- Server: context 32,768, one slot, existing prefix/KV behavior, API-reported cache hits
- Inference: temperature 0, maximum output 8,192 tokens, reasoning disabled, one repair call per case
- Correctness: the existing compile, verifier-load, functional, proof-shape, and source-semantics oracles
- Run order: source-only, matched raw tail, BPFix without help, full BPFix

The 18185 service was restored with the recorded model and command after explicit authorization. It was not reconfigured for 64K context, disabled caching, strict cache symmetry, or exclusive GPU use. Therefore, token counts are the cost result; wall time is recorded in the artifacts but is not used as a fairness claim.

## Results

| Condition | Repairs | Success rate | Input tokens | Cache hits | Non-cached input | Output tokens | Total tokens | Tokens / repair | Usage coverage |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| source-only | 24/75 | 32.0% | 50,627 | 1,575 | 49,052 | 51,829 | 102,456 | 4,269 | 75/75 |
| matched-raw-tail | 26/75 | 34.7% | 68,274 | 1,575 | 66,699 | 51,451 | 119,725 | 4,605 | 75/75 |
| bpfix-no-help | 29/75 | 38.7% | 70,206 | 1,575 | 68,631 | 43,768 | 113,974 | 3,930 | 75/75 |
| bpfix-neutral | 38/75 | 50.7% | 73,534 | 1,554 | 71,980 | 51,769 | 125,303 | 3,297 | 75/75 |

All four summaries have 75 model calls and complete prompt, cached-prompt, completion, and total-token coverage. The service reported no reasoning-token field. A model response that could not be extracted as source is counted as a failed repair, while its API usage remains included.

The 95% Wilson intervals for the success rates are 22.5--43.2% (source-only), 24.9--45.9% (matched tail), 28.5--50.0% (no help), and 39.6--61.7% (full BPFix).

## Paired outcomes

| Comparison | First only | Second only | Both pass | Neither passes | Exact paired p-value |
|---|---:|---:|---:|---:|---:|
| matched-raw-tail vs. bpfix-no-help | 3 | 6 | 23 | 43 | 0.5078 |
| bpfix-no-help vs. bpfix-neutral | 1 | 10 | 28 | 36 | 0.0117 |

The p-values are two-sided exact McNemar tests over the discordant pairs. They are descriptive for this fixed workload, not a population-level generalization.

## Token-matching audit

The no-help target totals 70,206 input tokens. Complete-line raw suffixes total 68,274 tokens, so the aggregate under-budget gap is 1,932 tokens (2.75%; mean 25.76, median 18, maximum 151 tokens per case). Three cases match exactly, 20/75 are within 1%, and 64/75 are within 5%; the largest per-case relative gap is 16.55%. No raw suffix exceeds its target. For every case, the native `/v1/chat/completions/input_tokens` count stored by the matcher equals the prompt-token usage returned by the subsequent generation call.

Line alignment prevents arbitrary mid-line cuts but makes exact equality impossible for most cases. The remaining gap slightly favors the matched-tail baseline on input cost and should be disclosed.

## Interpretation

`bpfix-no-help` is descriptively better than the token-matched raw tail: it repairs 29 rather than 26 cases while using 5,751 fewer total tokens (4.8%). It consumes 1,932 more input tokens because of line-granularity gaps, but produces 7,683 fewer output tokens. The paired direction is favorable (6 versus 3 discordant wins), although this single 75-case run is not statistically decisive (`p=0.5078`). The defensible mechanism claim is therefore that proof-aware content improves the observed success--cost frontier over naive complete-line tail truncation on this deployment, not that a general causal effect has been established.

Adding the `help:` lines increases success from 29 to 38 repairs. It costs 3,328 additional input and 8,001 additional output tokens, for 11,329 more total tokens (9.9%), but reduces total tokens per successful repair by 16.1%, from 3,930 to 3,297. The paired result is 10 full-only wins versus one no-help-only win (`p=0.0117`). Thus explicit repair guidance has the clearest measured contribution: it moves to a higher-success point and improves aggregate token efficiency per successful repair, while no-help remains the lower-total-cost option.

The source-only control is cheapest but repairs only 24 cases. Full BPFix repairs 14 additional cases while using 22,847 more total tokens; its paired outcome against source-only is 16 full-only versus 2 source-only wins (`p=0.0013`). Across the four new conditions, source-only, no-help, and full BPFix are meaningful success--cost operating points, while no-help strictly dominates matched-tail in this run.

## Prior raw-log result as background

The earlier one-shot full-raw run repaired 21/75 cases and reported at least 359,072 input, 40,506 output, and 399,578 total tokens. Usage exists for 72/75 calls, so these are lower bounds. Full BPFix uses at least 79.5% fewer input tokens and at least 68.6% fewer total tokens while repairing 17 more cases. This old raw run is background evidence only; it is not the token-matched mechanism comparison.

## Scope and incident record

- This is one temperature-zero run per condition with one local 27B model, one main75 split, and the current 32K server configuration.
- Do not claim universality across models, context lengths, or workloads; dollar cost; reasoning-token reduction; or strict wall-time improvement.
- The initially launched server process exited after roughly 50 minutes, after the first 60 calls of an initial `bpfix-neutral` run. That invalid summary has only 60/75 usage coverage and is excluded: `full/20260802T080952373002Z-pid1112388/bpfix-neutral/summary.json`.
- The service was restored with the identical command, model SHA, and llama.cpp commit, and `bpfix-neutral` was rerun from the first case. The valid rerun has 75/75 usage coverage. Its cache-hit total is reported rather than assumed symmetric with earlier groups.

## Raw artifacts

- Source-only: `full/20260802T073105095759Z-pid1058068/source-only/summary.json`
- Matched raw tail: `full/20260802T074345660111Z-pid1071164/matched-raw-tail/summary.json`
- BPFix without help: `full/20260802T075855562289Z-pid1092324/bpfix-no-help/summary.json`
- Full BPFix: `full/20260802T082035959683Z-pid1127965/bpfix-neutral/summary.json`
- Joint result audit: passed with zero errors using `bpfix-bench/tools/audit_results.py --require-cost-metrics`
