# Baseline and Ablation Design

This document defines the baselines and ablations for an OSDI/EuroSys-style
evaluation of BPFix on `bpfix-bench`. It is intentionally limited to diagnostic
evaluation design: what each method may consume, what it must produce, how
failures are counted, and how results should be reported.

## Evaluation Goal

The primary question is whether BPFix adds useful diagnostic signal beyond the
raw Linux verifier output and beyond plausible message-level tools. The
evaluation should therefore separate three sources of improvement:

- better presentation of the final verifier rejection;
- better classification from known verifier messages;
- BPFix-specific analysis of verifier state traces, proof-loss transitions,
  source correlation, and taxonomy rendering.

The headline evaluation should run on the replayable cases listed by
`bpfix-bench/manifest.yaml`. Non-replayable legacy excerpts may be used only for
background discussion or stress testing, not for primary claims.

## Input Policy

All methods must use fresh replay logs captured from `bpfix-bench/cases`.

For each case, the harness must:

1. build and load the case using the benchmark replay path;
2. capture the verifier log emitted by that replay attempt;
3. record the kernel/environment identifier, timeout, exit status, and log
   digest;
4. pass the same captured log to every method in the comparison.

Methods must not read preserved legacy logs from `bpfix-bench/raw`, historical
reports, previous evaluation outputs, or hand-copied verifier snippets. They may
read case source files only when that method is explicitly source-aware in the
baseline definition below. Ground-truth labels are evaluation-only data and must
not be exposed to any method at inference time.

If replay produces no verifier rejection log, the case is marked
`replay_invalid` for that run and no diagnostic method is scored on it. The
replay failure must be reported in the artifact-validity table. A final
published evaluation run should have zero `replay_invalid` cases after running
`bpfix-bench/tools/validate_benchmark.py --replay bpfix-bench`; otherwise the diagnostic
denominator is smaller and the missing cases must be explained explicitly.

## Compared Methods

### B0: Verifier Raw Log

This is the lower bound and developer-status-quo baseline. It presents the fresh
raw verifier log without additional parsing, ranking, localization, or
classification.

Allowed input:

- fresh verifier log from replay;
- case identifier for bookkeeping only.

Output:

- the final verifier rejection line selected by a fixed harness rule;
- no taxonomy prediction unless the final line can be directly reported as
  `unknown`;
- no source span beyond line annotations already printed in the log.

Purpose:

- measures how often the kernel verifier output alone is sufficient for a human
  or downstream LLM to identify the class and likely fix site.

### B1: Regex/Error-Message Baseline

This baseline represents a credible shallow diagnostic tool. It matches the
selected verifier error message, and optionally nearby trailer lines, against a
fixed catalog of message patterns.

Allowed input:

- fresh verifier log from replay;
- frozen regex catalog and taxonomy mapping;
- no trace-state reconstruction;
- no backward slicing;
- no source file inspection except source locations already printed in the log.

Output:

- one taxonomy class or `unknown`;
- one error ID or handler ID;
- one rejected span if a line, instruction number, or source annotation is
  present in the log;
- one short explanation derived from the matched message.

Purpose:

- measures how much of BPFix's result can be recovered from surface verifier
  messages alone.

### B2: Pretty Verifier or Equivalent External Tool

Pretty Verifier, or a comparable public verifier-message explanation tool, should
be included if it can be run reproducibly on the replay logs. If Pretty Verifier
is used, pin the upstream commit, Python version, invocation, and any local
compatibility patches. If it cannot run on a material fraction of the benchmark,
report it as an external-tool feasibility baseline rather than silently dropping
it.

Allowed input:

- fresh verifier log from replay;
- compiled object files only if they are produced by the same replay run and are
  made available for every method with the same source-aware status;
- no access to ground truth.

Output:

- tool-native explanation;
- normalized taxonomy class when a deterministic mapping from the tool's handler
  or message exists;
- source location only when produced by the tool under the same artifact policy.

Failure handling:

- crash: counted as `crash`, taxonomy `unknown`, localization miss;
- unhandled message: counted as `unhandled`, taxonomy `unknown`;
- no output: counted as `no_output`.

Purpose:

- compares BPFix against an independent external implementation, while making
  clear whether the external tool is fundamentally single-line/message-oriented
  or can consume full verifier traces.

### B3: LLM + Raw Log

This baseline tests whether a general-purpose model can infer useful diagnostics
from the same raw material that a developer sees.

Allowed input:

- fresh verifier log from replay;
- case source file only if the prompt variant is explicitly named
  `LLM+raw-log+source`;
- a fixed prompt that asks for taxonomy class, root-cause location, confidence,
  and concise rationale.

Disallowed input:

- BPFix intermediate artifacts;
- BPFix rendered diagnostics;
- ground-truth labels;
- historical accepted fixes unless the experiment is explicitly a repair
  experiment rather than diagnostic evaluation.

Output:

- taxonomy class;
- root-cause instruction/source location when predicted;
- fix category or brief fix rationale if requested by the metric;
- parseable JSON to avoid evaluator discretion.

Purpose:

- separates BPFix's structured analysis from the capability of a strong model
  reading raw verifier output.

### B4: LLM + Structured BPFix

Use this method only if the evaluation includes an LLM-assisted diagnosis or
repair workflow that consumes BPFix output. It is not a replacement for the non-LLM
BPFix pipeline; it is a downstream-consumer baseline.

Allowed input:

- fresh verifier log from replay;
- BPFix structured diagnostic JSON produced from that same log;
- case source file if the corresponding raw-log LLM source variant also gets it.

Output:

- same schema as `LLM+raw-log` so that the difference is attributable to the
  structured BPFix diagnostic.

Purpose:

- measures whether BPFix's structured output improves an LLM consumer over raw
  logs alone.

Reporting rule:

- never compare `LLM+structured BPFix` only against non-LLM baselines. Pair it
  with `LLM+raw-log` under the same model, prompt budget, temperature, source
  access, and retry policy.

### B5: BPFix Full Pipeline

This is the complete non-ablated BPFix diagnostic pipeline.

Allowed input:

- fresh verifier log from replay;
- case source and replay artifacts that are part of `bpfix-bench/cases`;
- frozen BPFix taxonomy, obligation catalog, parser, slicer, source correlator,
  and renderer versions.

Expected output:

- taxonomy class;
- BPFix error ID;
- proof status;
- rejected span;
- proof-lost or causal spans when present;
- source-correlated spans when available;
- rendered diagnostic text backed by structured JSON.

Purpose:

- tests the full claim: BPFix turns verifier traces into structured,
  source-correlated, actionable diagnostics.

## Ablation Matrix

Ablations should remove one BPFix component at a time while keeping the rest of
the pipeline, input logs, output schema, and evaluation harness unchanged.

| Method | Disabled component | Replacement behavior | Tests contribution to |
| --- | --- | --- | --- |
| `BPFix-full` | none | normal pipeline | headline result |
| `A1-no-trace-parser` | full state trace parser | final-message parse only, no register-state timeline | trace reconstruction |
| `A2-no-opcode-safety-monitor` | opcode-derived safety obligations and proof monitor | keep parsed trace but do not infer established/lost obligations from opcodes | safety-condition inference |
| `A3-no-slicer` | backward slicer, control dependence, and dataflow dependence | report rejection site only; no causal slice expansion | causal localization |
| `A4-no-controlflow-slice` | control-dependence slice only | keep data dependencies but omit branch/control predicates | branch-guard contribution |
| `A5-no-dataflow-slice` | data-dependence slice only | keep control predicates but omit register/value provenance | value provenance contribution |
| `A6-no-source-correlation` | BTF/log/source correlator | instruction-level spans only | source-level usability |
| `A7-no-taxonomy-renderer` | taxonomy-specific renderer and explanation templates | generic structured JSON converted to plain text | presentation and taxonomy-specific guidance |

The minimum ablation set for a full evaluation should include `A1`, `A2`, `A3`, `A6`,
and `A7`. `A4` and `A5` should be included if space permits or if the slicer is
a central contribution in the evaluation narrative.

## Metrics

Primary metrics:

- taxonomy accuracy against the adjudicated case label;
- localization accuracy for root-cause instruction or source span when ground
  truth is available;
- actionable diagnostic rate, judged by a fixed rubric;
- structured-output validity rate;
- crash, timeout, unhandled, and no-output rates.

Secondary metrics:

- exact error-ID accuracy where labels exist;
- multi-span diagnostic rate;
- earlier-root-cause rate, where proof loss precedes final rejection;
- source-correlation rate;
- case-weighted and family-weighted scores;
- runtime overhead per case.

For localization, report separate columns for instruction-level and source-level
matches. A method should not receive source-localization credit merely for
repeating a source annotation already present in the final raw log unless the
metric is explicitly `log-annotated source hit`.

## Fairness Rules

- Same replay log: all methods receive the identical fresh log bytes for a case.
- Same denominator: every successfully replayed manifest case remains in the
  denominator for every method. Replay-invalid cases are reported once as
  benchmark/harness failures, not as method-specific diagnostic failures.
- Same source policy: if one source-aware method receives `prog.c`, all source
  variants must be named explicitly; raw-log-only methods must remain separate.
- Same time budget: each method gets a fixed per-case timeout. LLM methods also
  get fixed retry and token budgets.
- Frozen versions: record BPFix commit, external-tool commit, model name,
  prompt version, kernel/environment ID, and benchmark manifest digest.
- No tuning on test labels: regex catalogs, prompts, and renderer rules must be
  frozen before the final run.
- No hidden fallback: a method that fails may emit `unknown`, but it must not
  call BPFix or another stronger method as a fallback.
- Normalized output: all methods are converted to the same evaluation schema by
  deterministic adapters checked into the artifact.
- Manual judging: if actionable quality is manually judged, use blinded outputs,
  at least two reviewers, adjudication, and report agreement.

## Failure Handling

Every per-case method run should end in exactly one status:

- `ok`: emitted a parseable diagnostic;
- `unknown`: emitted a valid diagnostic but no class or location;
- `unhandled`: external tool explicitly reported no matching handler;
- `invalid_output`: output could not be parsed into the evaluation schema;
- `timeout`: exceeded the per-case time budget;
- `crash`: process raised an exception or exited unexpectedly;
- `no_replay_log`: replay produced no usable verifier log, so methods were not
  scored for that case.

Accuracy metrics count only correct `ok` predictions as correct, but all
statuses remain visible in coverage tables. For LLM methods, malformed JSON after
the allowed retries is `invalid_output`, not a manual-repair opportunity.

## Result Table Layout

### Headline Diagnostic Table

| Method | Input | Taxonomy acc. | Root-cause loc. | Source loc. | Actionable | Valid output | Crash/timeout | Median time |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Verifier raw log | fresh replay log |  |  |  |  |  |  |  |
| Regex/error-message | fresh replay log |  |  |  |  |  |  |  |
| Pretty Verifier/ext. | fresh replay log |  |  |  |  |  |  |  |
| LLM+raw-log | fresh replay log |  |  |  |  |  |  |  |
| LLM+structured BPFix | log + BPFix JSON |  |  |  |  |  |  |  |
| BPFix full | log + replay artifacts |  |  |  |  |  |  |  |

### Ablation Table

| Method | Taxonomy acc. | Root-cause loc. | Multi-span | Source loc. | Actionable | Delta vs full |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BPFix full |  |  |  |  |  |  |
| A1-no-trace-parser |  |  |  |  |  |  |
| A2-no-opcode-safety-monitor |  |  |  |  |  |  |
| A3-no-slicer |  |  |  |  |  |  |
| A4-no-controlflow-slice |  |  |  |  |  |  |
| A5-no-dataflow-slice |  |  |  |  |  |  |
| A6-no-source-correlation |  |  |  |  |  |  |
| A7-no-taxonomy-renderer |  |  |  |  |  |  |

### Stratified Table

| Method | Source bugs | Lowering artifacts | Verifier limits | Environment mismatch | Verifier bugs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Verifier raw log |  |  |  |  |  |
| Regex/error-message |  |  |  |  |  |
| Pretty Verifier/ext. |  |  |  |  |  |
| LLM+raw-log |  |  |  |  |  |
| BPFix full |  |  |  |  |  |

Published results should report both case-weighted and family-weighted versions
of the headline table. Stratified reporting is required because message-level
baselines can look strong on direct helper-contract violations while failing on
lowering artifacts, proof-loss transitions, and cases where the final rejection
is only a symptom.
