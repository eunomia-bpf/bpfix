# Plan review

The first review found that matched-tail was incorrectly anchored to full BPFix while the intended mechanism comparison was matched-tail versus BPFix-no-help. It also required a reproducible complete-line suffix policy over the latest complete verifier load region and native chat-template-aware token counting.

The revised plan anchors each matched-tail prompt to that case's BPFix-no-help prompt, uses llama.cpp's `/v1/chat/completions/input_tokens` endpoint, evaluates complete-line suffixes without assuming tokenizer monotonicity, and records the target, matched count, gap, region, and suffix start line. It also scopes the paired comparisons and raw-token lower bound explicitly.

Final verdict: PASS. The four one-shot conditions are the minimum complete causal matrix; the offline 18185 service is an execution blocker, not a plan defect, and this task must not restart it.
