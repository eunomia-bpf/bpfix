# Experiment Plan: BPFix-Bench repair-signal ablations

## Research Question
- RQ exactly as written in the paper: Does a BPFix diagnostic help an LLM generate a working eBPF source repair more often than the raw verifier log alone?
- Specific uncertainty tested here: Whether the observed success/cost gain comes from shorter input, proof-aware content without explicit repair instructions, or the rendered `help:` instructions.
- Why the answer matters: The current raw-versus-BPFix result combines compression, localization, and repair guidance, so it cannot identify which signal makes the diagnostic useful.

## Paper-Value Admission
- Planned role: decisive mechanism ablation.
- Largest credible paper story this experiment could unlock: BPFix improves the repair-success/token-cost frontier beyond naive prompt truncation, and the experiment separates localization from explicit repair recipes.
- Strongest reviewer reject argument or load-bearing uncertainty addressed: BPFix may win only because its prompt is shorter or because `help:` gives away the repair.
- Independent evidence added beyond existing runs and published results: Per-case token-matched raw evidence, a no-help BPFix condition, and a source-only sanity control on the frozen main75 workload.
- Why the result is not tautological, already settled, or dominated: Existing full raw and `trimmed-raw` are not token-matched; no existing run removes BPFix help text.
- Paper decision if positive: Present repair quality as a success-token frontier and attribute the remaining matched-budget gain to proof-aware diagnostic content; report the marginal contribution of `help:` separately.
- Paper decision if contradictory, mixed, or inconclusive: Narrow the claim to practical compression/denoising or explicit guidance, depending on which ablation matches full BPFix.
- Best alternative experiment and why this one has higher decision value: More model families would broaden generality but would not resolve the causal mechanism behind the current gain.

## Expected And Alternative Outcomes
- Current expected answer: Token-matched raw tail improves over full raw but remains below BPFix-no-help; full BPFix gains further from repair hints.
- Strongest competing explanation: Source alone or a same-length raw suffix is sufficient, making BPFix's structured proof content unnecessary.
- Result that would contradict the expectation: Source-only or matched-tail equals or exceeds full BPFix at comparable or lower reported token cost.

## Published Precedent And Real Assets
- Existing protocol: The repository's frozen BPFix-Bench main75 raw-versus-BPFix repair protocol; no external published protocol is claimed here.
- Official system/model/data/benchmark/tool and version: main75, Qwen3.6 27B Q4_K_M, llama.cpp commit `2d973636e292ee6f75fadcf08d29cb33511f509f`, kernel/toolchain and oracle recorded by the runner.
- What is reused: Existing runner, frozen cases/split, executable case oracles, OpenAI-compatible model path, and API-reported usage.
- Necessary deviations or custom glue: Two prompt transformations in the existing runner: token-matched latest-load-region tail and removal of lines beginning with `help:`. A neutral evidence label is shared by the three diagnostic conditions. Token counts use llama.cpp's native `/v1/chat/completions/input_tokens` endpoint with the same system/user messages and chat template as generation.

## Comparison
- Proposed system or method: Full BPFix diagnostic under a neutral evidence label.
- Main baselines and the competing position each represents: Existing full raw result represents current practice; token-matched raw tail represents naive compression at the same input budget.
- Why each main baseline needs a matched run instead of citation alone: The comparison requires the same main75 cases, model tokenizer, prompt serialization, and executable oracle.
- Controls or ablations, labeled separately: source-only sanity control; BPFix-no-help component ablation.
- Conclusion if each main baseline matches or wins: A matched-tail win attributes the practical gain to compression rather than proof-aware structure; a no-help drop attributes some gain to explicit repair instructions; a source-only win challenges the need for diagnostic evidence on main75.
- Information, tuning, and compute fairness: Same source, system prompt, neutral evidence label, temperature 0, maximum output 8192, one call per case, and oracle. Matched tail is the largest complete-line suffix of the latest complete `BEGIN PROG LOAD LOG`--`END PROG LOAD LOG` region whose fully serialized chat prompt does not exceed that case's BPFix-no-help prompt tokens. The runner evaluates line-aligned suffixes and does not assume tokenizer monotonicity.
- Split or leakage rule when relevant: No reference fix, oracle implementation, hidden predicate, or BPFix text enters source-only or matched-tail.

## Workloads And Metrics
- Real workloads or tasks: Frozen `bpfix-bench/splits/main.txt`, 75 repair tasks.
- Primary metrics: Oracle-valid one-shot repairs and API-reported total tokens across all 75 calls.
- Correctness check or ground truth: Existing compile, verifier-load, functional, proof-shape, and source-semantics case oracles.
- Repetitions, seeds, and uncertainty: One temperature-zero run per condition; report paired outcomes and scope the result to this deployment/workload.
- Cost estimate when material: 300 one-shot calls for four new conditions; reuse the prior 75-call full-raw checkpoint. Record input, cached input, output, and total tokens; do not claim wall-time fairness.

## Planned Runs
| Run group | Role | Workload | System/method | Repetitions | Decision consequence |
|---|---|---|---|---:|---|
| source-only | sanity control | main75 | buggy source, no verifier evidence | 1 | Tests whether diagnostic evidence is needed |
| matched-tail | compression baseline | main75 | source plus per-case token-matched raw-log suffix | 1 | Separates naive compression from proof-aware content |
| no-help | component ablation | main75 | source plus BPFix diagnostic with `help:` lines removed | 1 | Measures contribution of explicit repair instructions |
| full-neutral | proposed | main75 | source plus full BPFix diagnostic | 1 | Reference for the two mechanism ablations |

## Execution
- Authoritative command or workflow: `bpfix-bench/tools/run_suite.py` with one attempt and each planned prompt mode against the existing `http://127.0.0.1:18185/v1` service.
- Real preflight case: `alu32_pointer_cookie_001` once per new prompt transformation, using the real model endpoint and executable oracle.
- Full completion rule: All four modes reach terminal status for all 75 cases; all model calls have reported prompt, cached-prompt, completion, and total usage; prompt matching is audited per case. Each matched-tail result records its no-help target tokens, matched tokens, gap, selected latest-load region, and suffix start line.
- Raw-result path: `bpfix-bench/results/ablation-main75-current-server/`.
- Checkpoint or recovery approach: One result directory per mode; keep every per-case prompt, response, candidate, oracle output, and summary.

## Interpretation
- Positive result: At equalized input budget, BPFix-no-help repairs more cases than matched tail; full BPFix quantifies the additional value of repair hints. Primary paired comparisons are no-help versus matched-tail and full-neutral versus no-help.
- Negative or contradictory result: Matched tail or source-only matches full BPFix, so the mechanism claim is narrowed to compression/denoising or the benchmark's source cues.
- Mixed or inconclusive result: Report category-specific paired outcomes and do not make a global localization claim if usage coverage or matching fails.
- Target paper figure or table: One table with condition, one-shot repairs, input/cache/output/total tokens, tokens per repair, and paired wins/losses for no-help versus matched-tail and full-neutral versus no-help.

## Reproducibility Notes
- Software and data versions: Git commit and toolchain captured by each summary; frozen split SHA-256 audited by the existing tools.
- Config and seed notes: Temperature 0, maximum output 8192, timeout 900 seconds, existing 32K cached server, one-shot only.
- Known deviations: The service is currently offline and will not be restarted by this task; real preflight/full execution waits for the existing service to be restored. Run order/cache are recorded, so no wall-time claim is made. The reused full-raw result has 7 calls without usage, so its token cost remains a lower bound and is background rather than a matched mechanism comparison.
