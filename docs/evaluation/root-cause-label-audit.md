# Root-Cause Label Audit

This document records the current root-cause localization label status for the
235 replayable cases in `bpfix-bench/manifest.yaml`.

Instruction localization is not the right denominator for every verifier
failure. Some failures are best localized to a source span, declaration, map or
BTF metadata, environment assumption, verifier scope, or analysis limit. Metrics
must therefore report the eligible denominator for each localization target.

## Current Coverage

Current `label.root_cause_insn_idx` coverage:

| metric | cases |
| --- | ---: |
| replayable cases | 235 |
| cases with `root_cause_insn_idx` | 140 |
| cases without `root_cause_insn_idx` | 95 |

Missing instruction labels by source:

| source_kind | missing instruction labels |
| --- | ---: |
| `github_issue` | 18 |
| `github_commit` | 24 |
| `stackoverflow` | 53 |

Kernel selftest cases currently all have instruction-level root-cause labels.

## Interpretation For Metrics

Do not report instruction localization over all 235 cases unless the table is
explicitly labelled as "all-case coverage". Instead:

- Diagnostic and taxonomy accuracy can use all replayable cases.
- Instruction localization should use cases whose target kind is an
  instruction-level verifier event.
- Source-span localization should use cases whose target kind is source-level
  code.
- Declaration, metadata, environment, and verifier-scope targets should be
  scored as routing/diagnostic-target correctness, not as instruction-local
  distance.

The benchmark should distinguish "the tool found the rejected instruction" from
"the tool found the root cause." Those are often different locations.

## Next Labeling Work

Before making headline localization claims:

1. Add or verify `localization_target_kind` for all 235 replayable cases.
2. Fill `root_cause_insn_idx` only where an instruction-level target is
   meaningful.
3. Fill `root_cause_source_span` and acceptable alternate spans for source-level
   targets.
4. Keep environment, declaration, metadata, and verifier-scope cases out of
   instruction-distance denominators.

Historical case lists for earlier audits remain in `docs/tmp/` and are not the
current denominator.
