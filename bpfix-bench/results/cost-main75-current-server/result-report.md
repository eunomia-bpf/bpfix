# Main-75 repair success–cost result

## Question and hypothesis

Does the BPFix diagnostic prompt improve the repair success–cost tradeoff relative to the raw verifier prompt on the same 75-case split?

Hypothesis: BPFix reaches at least the raw repair success with fewer reported tokens at the one-attempt and two-attempt checkpoints.

## Fixed setup

- Split: `bpfix-bench/splits/main.txt` (75 cases)
- Model: `Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M`
- Endpoint: `http://127.0.0.1:18185/v1`
- Existing server: context 32,768, prompt/KV caching enabled, parallelism 1
- Temperature: 0
- Maximum output: 8,192 tokens per call
- Maximum repair attempts: 2
- Run order: raw, then BPFix
- Git commit: `f5293abc67efda3df7f99817401e98090f5895ec`

The server was not restarted or reconfigured between runs. The experiment does not claim strict wall-time fairness or cold-cache symmetry.

## Results

| Checkpoint | Mode | Success | Calls | Input tokens | Cached input | Non-cached input | Output tokens | Total tokens | Usage coverage |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 attempt | raw | 21/75 (28.0%) | 75 | 359,072 | 1,512 | 357,560 | 40,506 | 399,578 | 72/75 |
| 1 attempt | BPFix | 38/75 (50.7%) | 75 | 73,684 | 1,575 | 72,109 | 43,475 | 117,159 | 75/75 |
| 2 attempts | raw | 32/75 (42.7%) | 129 | 702,022 | 60,028 | 641,994 | 75,734 | 777,756 | 122/129 |
| 2 attempts | BPFix | 44/75 (58.7%) | 112 | 185,314 | 2,352 | 182,962 | 66,002 | 251,316 | 112/112 |

Raw token totals are sums over usage-bearing calls and therefore lower bounds: 3 raw calls at the first checkpoint and 7 by the second checkpoint were rejected with HTTP 400 without usage. All seven missing-usage calls came from raw prompts too large for the current 32K-context service. BPFix had complete usage coverage and no model-call errors.

At one attempt, BPFix improves success by 22.7 percentage points while reducing reported total tokens by at least 70.7%. At two attempts, it improves success by 16.0 percentage points while reducing reported total tokens by at least 67.7%. Reported total tokens per successful repair decrease from at least 19,028 to 3,083 at one attempt (at least 83.8%) and from at least 24,305 to 5,712 at two attempts (at least 76.5%).

The paired outcomes are also favorable: at one attempt, 19 cases pass only with BPFix and 2 only with raw; at two attempts, the counts are 14 and 2.

As a robustness check, excluding every case with missing raw usage leaves 72 complete cases at the first checkpoint and 71 at the second. BPFix still leads 37 versus 21 successes with 72.7% fewer total tokens at one attempt, and 43 versus 32 successes with 72.3% fewer total tokens at two attempts. The observed advantage is therefore not explained only by the four raw cases rejected by the 32K deployment.

## Interpretation

The hypothesis is supported for this model, split, and existing 32K cached server. BPFix is on a strictly better observed success–cost frontier at both checkpoints: it repairs more cases with fewer reported total tokens. Because the raw totals omit rejected calls, the reported token reductions are conservative lower bounds. The context-limit rejections should be disclosed as part of the result rather than treated as zero-token calls.

The result does not establish a wall-time speedup, dollar cost, reasoning-token reduction, or universality across models and context sizes. It is one deterministic run and should be presented as strong descriptive evidence for this deployment and workload.

## Raw artifacts

- Raw summary: `20260801T075920882474Z-pid3975799/raw/summary.json`
- BPFix summary: `20260801T082437160849Z-pid4040619/bpfix/summary.json`
- Joint audit: passed with zero errors using `bpfix-bench/tools/audit_results.py`
