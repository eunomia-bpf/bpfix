# BPFix Evaluation Metrics

This document defines metrics for evaluating BPFix on `bpfix-bench`.
It is limited to metric definitions, ground-truth requirements, scoring
rules, exclusions, and reporting slices.

All primary diagnostic metrics must be grounded in locally replayed verifier
reject logs, not only in checked-in historical logs. A case is eligible for
primary evaluation only after the benchmark harness compiles the benchmark
program, loads it with the configured local verifier stack, records the reject
result, and stores the exact verifier log used as BPFix input.

## Evaluation Unit

The unit of evaluation is one replayed benchmark case:

- `case_id`
- source stratum, currently kernel selftest, GitHub issue, or Stack Overflow
- language/frontend, if applicable
- compiler, compiler version, flags, target architecture, kernel version,
  `bpftool` version, libbpf version, BTF availability, and program type
- source file and source revision
- locally replayed verifier outcome
- locally replayed verifier reject log
- BPFix diagnostic output
- optional repair output, if a repair system is evaluated

The primary denominator for diagnostic metrics is the set of eligible cases
whose local replay rejects with the expected failure family and yields a
parseable verifier log. Cases that do not locally reproduce the intended
reject must be excluded from primary diagnostic metrics and reported
separately.

## Required Ground Truth Labels

Each benchmark case needs the following labels before it can contribute to
the corresponding metrics.

### Reproduction Labels

- `expected_replay_status`: expected local replay result, normally
  `verifier_reject`
- `accepted_kernel_range` or tested kernel identity for which the label is
  valid
- `expected_reject_signature`: stable substring or structured verifier event
  that identifies the intended rejection
- `quarantine_reason`, if the case is known to be flaky, environment-bound, or
  no longer reproducible

### Diagnostic Labels

- `root_cause_summary`: concise human label for the underlying cause
- `root_cause_kind`: normalized cause type, such as missing bounds check,
  stale pointer proof, helper contract violation, invalid map definition,
  unavailable helper, verifier complexity limit, or frontend lowering artifact
- `taxonomy_class`: one of the benchmark taxonomy classes, for example
  `source_bug`, `lowering_artifact`, `verifier_limit`, `environment_or_configuration`, or
  `verifier_false_positive`
- `verifier_error_class`: normalized verifier error family extracted from the
  replayed log
- `required_preconditions`: facts that must be mentioned for a correct
  diagnosis, such as nullable pointer, packet upper bound, map value size, loop
  bound, helper availability, or BTF metadata
- `forbidden_claims`: known misleading claims that should receive no credit
  when they drive the answer

### Localization Labels

- `reject_insn_idx`: verifier instruction index reported at rejection
- `root_cause_insn_idx`: instruction index where the causal obligation is
  introduced or lost
- `root_cause_source_span`: canonical source file, start line/column, and end
  line/column for the root cause
- `localization_target_kind`: expected target granularity, such as
  `instruction`, `source_span`, `declaration_or_metadata`, `environment`,
  `verifier_scope`, `not_applicable`, or `insufficient_context`
- `reject_source_span`: source span corresponding to the rejected instruction,
  when different from the root cause
- `acceptable_source_spans`: alternate spans that should receive full or
  partial credit because they identify the same causal obligation
- `span_granularity`: expected granularity, such as expression, statement,
  declaration, loop, helper call, or function boundary

### Proof Labels

- `proof_status`: expected proof status, such as `never_established`,
  `established_then_lost`, `classification_only`, `not_applicable`, or
  `unknown`
- `proof_established_insn_idx`: instruction where the relevant verifier fact is
  first established, if any
- `proof_lost_insn_idx`: instruction where the relevant verifier fact is lost,
  if any
- `proof_obligation`: the verifier fact involved, such as pointer bounds,
  non-nullness, scalar range, stack initialization, reference lifetime, map
  value size, or helper argument type
- `proof_evidence`: verifier-log lines or structured events supporting the
  proof status

### Repair Labels

Repair labels are required only for experiments that evaluate generated
patches or fix recommendations.

- `repair_applicable`: whether a source repair is meaningful for this case
- `canonical_fix_strategy`: normalized strategy, such as add bounds check,
  preserve checked pointer expression, reload context pointer, initialize stack
  memory, use correct helper, change map declaration, reduce verifier state
  space, or target compatible environment
- `acceptable_fix_strategies`: alternate strategies that are semantically
  equivalent
- `fixed_source` or `fix_oracle`: reference patch, accepted rewrite, or
  executable oracle for validating repairs
- `negative_repair_constraints`: changes that must not be counted as success,
  such as deleting program logic, weakening the benchmark assertion, changing
  program type without justification, or avoiding the rejected code path

## Diagnostic Correctness

Diagnostic correctness measures whether BPFix explains the cause of the
locally replayed verifier rejection.

### Exact Diagnostic Correctness

A case receives full credit if the diagnostic:

- identifies the same root cause as `root_cause_summary`
- states the relevant verifier obligation from `proof_obligation` or
  `required_preconditions`
- explains why the replayed verifier rejects, not merely where it rejects
- avoids any `forbidden_claims` that would change the diagnosis

Report:

- exact diagnostic accuracy: `correct / eligible_cases`
- macro-averaged exact accuracy over taxonomy classes
- macro-averaged exact accuracy over source strata

### Partial Diagnostic Correctness

Use a 0 to 1 score when exact binary scoring loses important distinctions.
The recommended rubric is:

| Component | Weight |
| --- | ---: |
| Correct verifier error family | 0.20 |
| Correct causal obligation | 0.30 |
| Correct causal mechanism | 0.30 |
| Correct environment/source distinction | 0.10 |
| No material false claim | 0.10 |

The case score is the sum of satisfied components. A material false claim
caps the score at 0.50. A diagnosis that contradicts the local replayed log
scores 0, even if it resembles the historical case description.

Report mean partial diagnostic score, median score, and the fraction of cases
with score at least 0.75.

## Root-Cause Localization

Localization measures whether BPFix points to the causal program location,
not only the verifier reject site.

### Instruction Localization

Compare predicted instruction indices with `root_cause_insn_idx`.

Report:

- exact root instruction accuracy: `predicted == root_cause_insn_idx`
- within-1, within-5, and within-10 instruction accuracy
- mean absolute instruction error
- median absolute instruction error
- root-before-reject detection for cases where
  `root_cause_insn_idx != reject_insn_idx`

Predictions that identify only `reject_insn_idx` receive full localization
credit only when the ground-truth root cause and reject instruction are the
same. Otherwise, they receive reject-site credit but not root-cause credit.

### Source-Span Localization

Compare predicted source spans with `root_cause_source_span` and
`acceptable_source_spans`.

Report:

- exact span match: same file and same start/end line after normalization
- line overlap F1: harmonic mean of line-level precision and recall
- token or column overlap F1 when column labels are available
- contains-root rate: predicted span contains the canonical root span
- contained-by-root rate: predicted span is contained within the canonical root
  span
- distance-to-root in lines for non-overlapping spans

Partial credit:

- 1.00: exact canonical span or listed acceptable equivalent
- 0.75: same causal statement/expression with minor boundary mismatch
- 0.50: same enclosing block, loop, function, or declaration but too broad
- 0.25: same file and nearby region, within 10 source lines, but not the
  causal construct
- 0.00: wrong file, unrelated code, or reject site only when root differs

For multi-span predictions, score the best span for recall-oriented metrics
and also report precision penalties: average number of predicted spans and
fraction of predictions with more than three spans.

## Proof-Event and Proof-Status Quality

Proof metrics evaluate whether BPFix reconstructs verifier reasoning events
from the replayed reject log.

### Proof Status

Compare predicted proof status with `proof_status`.

Report:

- proof-status accuracy
- macro F1 over proof-status classes
- confusion matrix, especially false `established_then_lost` predictions for
  non-lowering cases
- coverage: fraction of eligible cases with any proof-status prediction

If the ground-truth status is `not_applicable`, a prediction should receive
credit only if it explicitly avoids inventing a proof-loss narrative.

### Proof Events

Compare predicted proof-event locations and obligations with
`proof_established_insn_idx`, `proof_lost_insn_idx`, and `proof_obligation`.

Report:

- proof-established exact and within-5 instruction accuracy
- proof-lost exact and within-5 instruction accuracy
- proof-obligation accuracy
- event-pair accuracy: both establish and loss events correct when both are
  labeled
- event coverage: fraction of cases where BPFix emits the expected event type

Partial credit:

- 1.00: correct event type, obligation, and exact instruction
- 0.75: correct event type and obligation within 5 instructions
- 0.50: correct event type but wrong or incomplete obligation
- 0.25: correct general proof narrative but no usable event location
- 0.00: unsupported proof event, wrong direction of proof transition, or event
  contradicted by the replayed log

## Taxonomy and Error Classification

Taxonomy scoring evaluates whether BPFix classifies the failure at the level
needed for analysis and repair routing.

Report:

- taxonomy accuracy
- per-class precision, recall, and F1
- macro F1
- weighted F1
- balanced accuracy
- confusion matrix
- abstention rate, if the system can output `unknown`

Primary taxonomy classes must be scored separately from lower-level verifier
error families. A prediction can receive verifier-error-family credit without
receiving taxonomy credit when it recognizes the error string but assigns the
wrong source/category cause.

Partial taxonomy credit:

- 1.00: exact `taxonomy_class`
- 0.50: correct broad actionability group but wrong class, for example
  differentiating source-or-repairable from environment-or-not-repairable
- 0.25: correct verifier error family but wrong actionability group
- 0.00: unrelated class or unsupported default

When taxonomy is used to choose repairs, also report repair-routing accuracy:
the fraction of cases whose predicted class would select an appropriate repair
or no-repair path.

## Repair and Fix Success

Repair metrics apply only when an experiment evaluates generated fixes or fix
recommendations. They must be reported separately from diagnostic metrics.

### Fix Recommendation Quality

For natural-language or structured fix recommendations, report:

- fix-strategy accuracy against `canonical_fix_strategy` and
  `acceptable_fix_strategies`
- partial fix-strategy score using the repair rubric below
- no-op or non-actionable recommendation rate
- unsafe recommendation rate, where the suggestion would bypass verification,
  remove required behavior, or target an incompatible environment

Partial repair-strategy credit:

| Component | Weight |
| --- | ---: |
| Addresses the labeled root cause | 0.40 |
| Uses a verifier-compatible strategy | 0.30 |
| Preserves intended program semantics | 0.20 |
| Identifies when no source repair is appropriate | 0.10 |

If `repair_applicable` is false, full credit requires recommending no source
patch and correctly identifying the environment, verifier, or benchmark
condition. Proposing a source patch for a non-repairable case scores at most
0.25.

### Patch Validation

For generated source patches, report each stage with its own denominator:

- patch emission rate: patches emitted / repair-applicable cases
- apply rate: patches that apply cleanly / emitted patches
- compile rate: patched programs that compile / applied patches
- verifier pass rate: patched programs accepted by local verifier / compiled
  patches
- end-to-end repair success: verifier-accepted patched programs /
  repair-applicable cases
- semantic preservation rate, when benchmark-specific tests or equivalence
  checks exist

A verifier-accepted patch is not automatically a successful repair. It must
also preserve required behavior and satisfy `negative_repair_constraints`.
Patches that delete the rejected operation, change program type without a
ground-truth basis, alter map or context semantics to avoid the benchmark, or
depend on unavailable kernel features must be counted as failures.

## Runtime and Overhead

Runtime metrics must isolate replay overhead from BPFix analysis overhead.

Report:

- local replay compile time
- local replay verifier load time
- verifier log size in lines and bytes
- BPFix analysis wall-clock time
- peak resident memory for BPFix analysis
- number of verifier events parsed
- number of source/instruction correlation records built
- timeout rate
- failure rate by stage: compile, load, log capture, parse, analysis, render

Summaries must include median, mean, p90, p95, and maximum. Use the same
machine class, kernel, compiler, and timeout settings for comparative runs.
When comparing BPFix variants, report paired per-case deltas and confidence
intervals or bootstrap intervals.

Runtime metrics should be computed over all reproduced cases, including cases
where the diagnostic is wrong. Excluding hard cases from runtime summaries
must be explicitly reported.

## Reporting by Source and Category

Every headline metric must be accompanied by stratified reporting.

Required source strata:

- kernel selftests
- GitHub issues or pull requests
- Stack Overflow cases
- synthetic or reduced cases, if a future benchmark revision includes them
- any additional benchmark source used by `bpfix-bench`

Required category strata:

- taxonomy class
- verifier error family
- program type
- language/frontend
- root-cause distance bucket:
  - `0`: root and reject instruction are the same
  - `1-5`
  - `6-10`
  - `11-25`
  - `26+`
- replay status
- repair applicability

For each stratum, report case count, coverage, exact score, partial score, and
confidence interval when the stratum has enough cases. Strata with fewer than
five cases should be shown but not used for broad claims without qualification.

## Exclusions

Exclude the following from primary diagnostic, localization, proof, taxonomy,
and repair-success metrics:

- cases that do not locally replay to a verifier rejection
- cases whose replayed rejection does not match `expected_reject_signature`
- cases with missing or unparseable verifier logs
- quarantined cases
- duplicate cases where the same source, same root cause, and same verifier
  signature would overweight one bug
- cases used for prompt construction, rule authoring, model fine-tuning, or
  threshold selection, unless reported only in a training/development split
- cases where the ground truth lacks the label required for the metric being
  reported
- repair cases where the patch is validated against a different kernel,
  compiler, flags, architecture, or program type than the replayed reject,
  unless the metric is explicitly cross-environment generalization

Do not exclude wrong predictions, parser failures, timeouts, abstentions, or
cases where BPFix emits no source span. These are valid failures for the
corresponding metrics and must remain in the denominator.

## Statistical Reporting

Report exact binomial or bootstrap confidence intervals for proportions.
For paired comparisons between BPFix variants or between BPFix and a baseline,
use paired tests, such as McNemar's exact test for binary outcomes and paired
bootstrap intervals for partial scores and runtimes.

Primary claims should use the held-out primary split. Development, ablation,
and prompt-selection results must be labeled separately. If multiple kernels
or compiler versions are evaluated, report per-environment metrics and the
intersection set of cases reproduced across all environments.

## Minimum Result Artifact

Each evaluation run should emit a machine-readable artifact with at least:

- run metadata and environment versions
- case eligibility and exclusion reason
- replayed verifier status and reject log identifier
- ground-truth label version
- BPFix prediction fields used for each metric
- per-case binary and partial scores
- aggregate metrics and stratified metrics

The artifact must be sufficient to recompute all published evaluation tables
without rerunning BPFix, except for explicitly marked runtime measurements.
