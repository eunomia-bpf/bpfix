# Independent result review

Verdict: PASS with scope limitations.

The reviewer independently recomputed the four valid summaries and confirmed that their model, llama.cpp, inference configuration, repository commit, split identity, ordered 75-case set, and one-shot policy match. All four runs have 75/75 coverage for prompt, cached-prompt, completion, and total tokens. The interrupted `bpfix-neutral` run at `full/20260802T080952373002Z-pid1112388/` has only 60/75 usage coverage and is correctly excluded.

## Recomputed aggregates

| Condition | Repairs | Input | Cached | Output | Total | Total / repair |
|---|---:|---:|---:|---:|---:|---:|
| source-only | 24 | 50,627 | 1,575 | 51,829 | 102,456 | 4,269 |
| matched-raw-tail | 26 | 68,274 | 1,575 | 51,451 | 119,725 | 4,605 |
| bpfix-no-help | 29 | 70,206 | 1,575 | 43,768 | 113,974 | 3,930 |
| bpfix-neutral | 38 | 73,534 | 1,554 | 51,769 | 125,303 | 3,297 |

The paired outcomes also match the report:

- Matched tail versus no help: 23 both pass, 3 tail-only, 6 no-help-only, and 43 neither; two-sided exact McNemar `p=0.5078125`.
- No help versus full BPFix: 28 both pass, 1 no-help-only, 10 full-only, and 36 neither; `p=0.01171875`.

## Matching audit

The per-case no-help targets sum to 70,206 tokens and the selected raw tails sum to 68,274 actual API prompt tokens. The 1,932-token aggregate gap is 2.7519%; the per-case gap has mean 25.76, median 18, range 0--151, and maximum relative gap 16.55%. Three cases match exactly. Every selected tail remains at or below its target, and all 75 stored matcher counts equal the subsequent generation API prompt-token counts.

## Required scope

- Describe the no-help advantage over matched tail as a descriptive improvement or observed frontier result, not a statistically established general causal effect.
- Attribute the clearest measured marginal gain to `help:`: 29 to 38 repairs, 10 versus 1 discordant wins, and 3,930 to 3,297 aggregate tokens per repair, with 9.9% more aggregate total tokens.
- Treat the old raw prompt, cached, output, and total counts as lower bounds because its one-shot usage coverage is 72/75. It is background, not the matched mechanism comparison.
- Do not claim cross-model universality, wall-time improvement, reasoning-token reduction, or dollar cost.

Recommended paper wording:

> On this one-model, one-shot main75 deployment, BPFix without `help:` descriptively dominated a per-case budget-capped raw-log tail---29 versus 26 repairs and 113,974 versus 119,725 total tokens---but the paired success difference was inconclusive (`p=0.5078`). Adding `help:` increased repairs from 29 to 38 (10 versus 1 discordant wins, `p=0.0117`) and reduced aggregate tokens per successful repair from 3,930 to 3,297, while increasing aggregate total tokens by 9.9%.

