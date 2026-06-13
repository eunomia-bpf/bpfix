# Blind Audit Results: 60-Case Stratified Sample

This file records two independent scorer passes over
`docs/evaluation/blind-audit-sample-60.json`.

The audit is not a user study.  It is a blind expert-style scoring pass over
three anonymized outputs:

- `M1`: terminal verifier message only.
- `M2`: terminal-message dictionary baseline.
- `M3`: full-log BPFix diagnostic.

Sample construction:

- seed: `bpfix-blind-audit-v1`
- size: 60
- taxonomy: 24 lowering artifact, 11 environment/configuration, 9 verifier
  false positive, 4 verifier limit, 12 source bug
- source: 24 Stack Overflow, 21 GitHub commit, 7 GitHub issue, 8 kernel
  selftest

## Scorer A

Required proof:

| method | exact | partial | miss |
| --- | ---: | ---: | ---: |
| M1 | 0 | 60 | 0 |
| M2 | 8 | 43 | 9 |
| M3 | 16 | 42 | 2 |

Root localization:

| method | exact | near | miss | na |
| --- | ---: | ---: | ---: | ---: |
| M1 | 0 | 0 | 26 | 34 |
| M2 | 0 | 0 | 26 | 34 |
| M3 | 15 | 3 | 8 | 34 |

Help quality and next action:

| method | correct | partial | unsafe | none |
| --- | ---: | ---: | ---: | ---: |
| M1 | 0 | 0 | 0 | 60 |
| M2 | 0 | 46 | 14 | 0 |
| M3 | 24 | 22 | 14 | 0 |

## Scorer B

Required proof:

| method | exact | partial | miss |
| --- | ---: | ---: | ---: |
| M1 | 0 | 60 | 0 |
| M2 | 15 | 28 | 17 |
| M3 | 22 | 20 | 18 |

Root localization:

| method | exact | near | miss | na |
| --- | ---: | ---: | ---: | ---: |
| M1 | 0 | 0 | 27 | 33 |
| M2 | 0 | 0 | 27 | 33 |
| M3 | 16 | 5 | 6 | 33 |

Help quality and next action:

| method | correct | partial | unsafe | none |
| --- | ---: | ---: | ---: | ---: |
| M1 | 0 | 0 | 0 | 60 |
| M2 | 0 | 50 | 10 | 0 |
| M3 | 23 | 23 | 14 | 0 |

## Interpretation

Both scorers agree on the main result: BPFix is the only method that provides
root localization and substantially more correct actionable help.  Terminal
dictionary baselines can match coarse categories for obvious environment and
limit messages, but they do not provide root spans or proof-lifecycle context.

Both scorers also found unsafe BPFix help in 14/60 cases, especially for stack
alignment, false-positive range-precision cases, and verifier-specific
lifecycle/order constraints.  The paper should therefore claim a localization
and help-quality advantage on this sample, not complete diagnostic correctness.
