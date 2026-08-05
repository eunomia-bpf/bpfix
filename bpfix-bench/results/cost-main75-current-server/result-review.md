# Independent result review

Verdict: PASS with scope limitations.

The reviewer independently recomputed both checkpoints and matched the success counts, model-call counts, token fields, usage coverage, per-success costs, relative changes, and paired audit. The tested hypothesis is supported: on the current 27B, 32K-context cached deployment and main75 workload, BPFix improves the observed repair-success/token-cost frontier.

Required reporting constraints:

- Treat raw totals as known lower bounds because 3/75 calls at one attempt and 7/129 calls at two attempts lack usage after HTTP 400 rejection.
- Do not replace missing usage with zero.
- Say that the requests were rejected under the current 32K deployment; the artifacts do not retain the HTTP response body needed to assert a more specific server error.
- Do not claim wall-time fairness, dollar cost, reasoning-token savings, statistical generality, or universality across models/context lengths.
- The service reported no reasoning-token usage.

The reviewer also checked the complete-usage subset. After excluding every case with a missing raw call, BPFix remains ahead at both checkpoints: 37 versus 21 successes and 72.7% fewer total tokens on 72 one-attempt cases; 43 versus 32 successes and 72.3% fewer total tokens on 71 two-attempt cases.
