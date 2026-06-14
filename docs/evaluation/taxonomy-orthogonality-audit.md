# Taxonomy Orthogonality Audit

This document records the pre-migration `bpfix-bench` root-cause label audit
that motivated the orthogonal taxonomy cleanup. It covers the 235 replayable
cases under
`bpfix-bench/cases/*/case.yaml` and the current taxonomy/catalog inputs:

- `bpfix-bench/taxonomy.yaml`
- `docs/evaluation/legacy-catalogs/error_catalog.yaml`
- `docs/evaluation/legacy-catalogs/obligation_catalog.yaml`
- `docs/evaluation/metrics.md`
- `docs/evaluation/baselines.md`

No `bpfix-bench/cases/*.yaml` file was edited while producing the audit
snapshot below.

## Migration Status

The blocking migration described in this audit has since been applied. Active
`label.taxonomy_class` values are now restricted to the mutually exclusive
primary classes:

| active primary class | cases |
| --- | ---: |
| `source_bug` | 187 |
| `lowering_artifact` | 24 |
| `environment_or_configuration` | 11 |
| `verifier_false_positive` | 9 |
| `verifier_limit` | 4 |
| **total** | **235** |

Historical references below to `env_mismatch`, `stack_safety`, and
`build_configuration` describe the pre-migration labels. They are not active
primary taxonomy classes.

## Finding

The pre-migration labels mixed at least two dimensions in `label.taxonomy_class`.
`source_bug`, `lowering_artifact`, `env_mismatch`, and `verifier_limit` are
root-cause-layer labels, while `stack_safety` and `build_configuration` were
mechanism or configuration labels. This is not orthogonal enough for
OSDI/SOSP-style claims because the benchmark can double-count the same concept
as either a primary class or a secondary mechanism.

The cleanup should keep one mutually exclusive primary root-cause axis and move
mechanisms such as stack safety, helper contracts, nullability, bounds checks,
BTF metadata, build flags, and verifier budgets into secondary tags.

## Proposed Label Scheme

### Primary Axis

Use exactly one primary value per case in `label.taxonomy_class`:

| primary class | definition | repair-routing meaning |
| --- | --- | --- |
| `source_bug` | The source/reproducer violates a verifier-enforced source, API, memory-safety, lifetime, type, or stack contract in the intended target environment. | Source-level repair is appropriate. |
| `lowering_artifact` | The source-level proof or intended invariant is present, but compilation/lowering produces verifier-hostile bytecode that loses or obscures the proof. | Source rewrite, compiler flag, or lowering-aware idiom may repair it, but the root cause is the source-to-bytecode translation. |
| `environment_or_configuration` | The program assumes a kernel, BTF, loader, attach type, helper/kfunc availability, map relocation, build option, or deployment configuration that is not present in the replay environment. | Fix the environment/configuration or target a compatible feature set; do not score as an ordinary memory-safety source bug. |
| `verifier_limit` | The program is plausibly safe for the intended environment, but the verifier's bounded analysis, state exploration, loop proof, or stack-budget model cannot prove it. | Refactor for verifier tractability; do not treat as missing safety precondition. |
| `verifier_false_positive` | The bytecode is semantically safe, but the verifier rejects it conservatively or incorrectly. Stronger evidence may identify an upstream verifier bug. | Kernel/verifier fix or verifier-friendly semantic-preserving workaround. |

`unknown` should remain an adjudication status, not a primary class for final
published metrics.

### Secondary Axes

Keep these dimensions independent of the primary axis:

| axis | suggested field | examples |
| --- | --- | --- |
| mechanism | `label.mechanism_tags` | `stack_safety`, `packet_bounds`, `map_value_bounds`, `scalar_range`, `pointer_provenance`, `nullability`, `reference_lifetime`, `dynptr_lifecycle`, `iterator_lifecycle`, `irq_rcu_lock_discipline`, `helper_contract`, `context_access`, `btf_metadata`, `build_config`, `loader_relocation`, `program_type_capability`, `kernel_capability`, `verifier_budget`, `loop_bound`, `combined_stack_budget` |
| proof obligation | `label.obligation_ids` | Existing `BPFIX-O001` through `BPFIX-O023` identifiers. |
| error family | existing `label.error_id` | Existing `BPFIX-E001` through `BPFIX-E023` identifiers. |
| repair strategy | existing `label.fix_type`, optionally `label.fix_tags` | `add_bounds_check`, `add_null_check`, `clamp_scalar`, `preserve_pointer_provenance`, `initialize_stack`, `balance_release`, `move_to_map_storage`, `change_prog_type`, `regenerate_btf`, `fix_loader_relocation`, `change_compiler_flags`, `reduce_stack`, `rewrite_loop`, `split_program`. |
| evidence | `label.classification_evidence` or `label.evidence_tags` | `source_check_present`, `proof_established_then_lost`, `spill_reload_loss`, `cfg_join_widening`, `accepted_with_equivalent_lowering`, `missing_kernel_feature`, `missing_btf`, `loader_relocation_missing`, `analysis_budget_exceeded`, `upstream_verifier_fix`. |

The existing `root_cause_description`, `confidence`, `fix_type`, `error_id`,
and localization fields should be retained. The minimum new field needed for
orthogonality is `mechanism_tags`; `obligation_ids` and evidence tags are
recommended for lowering and verifier-limit cases because those classes are
easy to overclaim.

## Decision Rules

Apply these rules in order after confirming that the local replay rejection
matches the intended case.

### 1. `verifier_false_positive`

Use `verifier_false_positive` only with independent evidence that the rejected
program is semantically safe:

- an upstream kernel/verifier patch accepts the same intended program without a
  source or environment change;
- a minimized reproducer isolates a verifier regression across kernel versions;
- the log or kernel report shows an internal verifier inconsistency, warning,
  crash, or demonstrably incorrect state transition.
- the verifier rejects a range, relation, or state merge that can be manually
  proved safe without adding a new semantic precondition.

Do not use this class when a source rewrite, build configuration change, helper
selection change, or verifier-friendly refactor is the only evidence.

### 2. `environment_or_configuration`

Use `environment_or_configuration` when the failure is caused by a mismatch
between the program's assumed target and the replay target:

- helper, kfunc, map feature, attach type, or program type is unavailable or
  forbidden in the selected environment;
- BTF, CO-RE, func info, reference metadata, context layout, or map relocation
  is absent, malformed, or built for the wrong target;
- build or compiler configuration creates bytecode outside the benchmark's
  intended BPF target contract, for example unoptimized builds leaving indirect
  helper calls or unknown opcodes;
- the same source/bytecode is expected to verify under a different declared
  kernel, program type, loader, build flag set, or runtime capability.

Do not use this class for ordinary helper argument preconditions such as a
nullable pointer, wrong register type, missing bounds check, unbalanced
reference, or invalid stack slot. Those are `source_bug` with mechanism tags
such as `helper_contract`, `nullability`, or `stack_safety`.

### 3. `lowering_artifact`

Use `lowering_artifact` only when the source-level safety argument is already
present and the rejection is best explained by the compiler/lowering path. At
least one strong evidence item should be recorded, and for final published
labels two are preferable:

- a dominating source-level check or invariant exists before the rejected use;
- verifier trace shows the proof was established and then lost through a
  lowering-created spill/reload, register merge, CFG join, sign/width widening,
  pointer truncation, or helper-boundary artifact;
- an equivalent source rewrite, optimization setting, or hand-lowered bytecode
  verifies without adding a new semantic safety precondition;
- upstream commit or issue text identifies LLVM/BPF lowering, inlining,
  register allocation, stack layout, or source-to-bytecode shape as the cause;
- the rejected path is compiler-created or materially different from the
  source-level path the programmer wrote.

Disqualifiers:

- the source simply lacks the required bounds, null, lifetime, stack, or helper
  precondition;
- the accepted fix adds a new semantic check rather than preserving an existing
  one;
- evidence is only the verifier message family, for example `BPFIX-E005`
  scalar range or `BPFIX-E006` pointer provenance, with no source/bytecode
  proof-loss evidence.

When evidence is insufficient, classify the case as `source_bug` and add a
secondary tag such as `scalar_range`, `pointer_provenance`, or `bounds_check`.

### 4. `verifier_limit`

Use `verifier_limit` when the root cause is verifier tractability rather than a
missing safety precondition:

- terminal error is an analysis or resource limit, such as state explosion,
  one-million-instruction processing budget, loop bound proof failure, program
  size, or combined stack budget;
- the source can be manually argued safe under the intended environment;
- an equivalent refactor reduces verifier search or stack accounting without
  changing the semantic safety preconditions;
- different verifier versions or configurations accept the same safety argument
  due to analysis improvements.

Do not use `verifier_limit` for direct out-of-bounds stack writes, uninitialized
stack reads, nullable pointer use, missing packet/map bounds, or helper
argument contract violations. Those are source bugs even if the verifier's
error text mentions stack or range.

### 5. `source_bug`

Use `source_bug` as the default for a real missing or violated verifier
obligation in the intended environment:

- missing or non-dominating packet/map/stack bounds proof;
- nullable pointer used without a dominating non-null proof;
- uninitialized stack read or direct stack access outside allowed bounds;
- pointer provenance, scalar range, reference lifetime, dynptr, iterator, IRQ,
  RCU, lock, return-value, or helper-argument contract is violated by the
  source/reproducer;
- a source-level fix must add a new precondition, cleanup path, initialization,
  range clamp, or valid register/object relationship.

`stack_safety` is not a primary class. It is a mechanism tag that can appear
with `source_bug` for direct stack-memory violations or with `verifier_limit`
for combined-stack-budget proof limits.

## Pre-Migration Distribution

The 235 replayable cases had this primary-label distribution before migration:

| pre-migration `label.taxonomy_class` | cases |
| --- | ---: |
| `source_bug` | 167 |
| `lowering_artifact` | 47 |
| `env_mismatch` | 13 |
| `verifier_limit` | 4 |
| `stack_safety` | 3 |
| `build_configuration` | 1 |
| **total** | **235** |

Confidence distribution by pre-migration class:

| pre-migration class | high | medium | low | total |
| --- | ---: | ---: | ---: | ---: |
| `source_bug` | 86 | 79 | 2 | 167 |
| `lowering_artifact` | 4 | 40 | 3 | 47 |
| `env_mismatch` | 2 | 11 | 0 | 13 |
| `verifier_limit` | 2 | 2 | 0 | 4 |
| `stack_safety` | 0 | 3 | 0 | 3 |
| `build_configuration` | 0 | 1 | 0 | 1 |
| **total** | **94** | **136** | **5** | **235** |

Source strata:

| source kind | cases |
| --- | ---: |
| `kernel_selftest` | 85 |
| `stackoverflow` | 86 |
| `github_commit` | 46 |
| `github_issue` | 18 |

Other audit facts:

- All 235 cases have `capture.log_quality: trace_rich`.
- `label.label_source` counts are `external_replay_reconstruction` 105,
  `agree` 104, `manual_reconstruction` 17, and `adjudicated` 9.
- `external_match.status` counts are `not_applicable` 131, `exact` 42,
  `semantic` 37, and `partial` 25.
- `repair.eligible` is false for 203 cases and true for 32 cases.
- `bpfix-bench/taxonomy.yaml` now defines `verifier_false_positive`; the first
  lowering-candidate audit moved 9 replayable cases into that class.
- `stack_safety` and `build_configuration` were case labels but were not
  top-level classes in `bpfix-bench/taxonomy.yaml`.

If only the two off-axis labels are normalized, the provisional class counts
would be:

| proposed primary class | provisional cases | source of change |
| --- | ---: | --- |
| `source_bug` | 170 | Existing `source_bug` plus three pre-migration `stack_safety` cases. |
| `lowering_artifact` | 47 | Existing `lowering_artifact`, pending strict evidence audit. |
| `environment_or_configuration` | 14 | Existing `env_mismatch` plus one pre-migration `build_configuration` case. |
| `verifier_limit` | 4 | Existing `verifier_limit`, pending manual confirmation. |
| `verifier_false_positive` | 0 | No pre-migration primary label; introduced by the later lowering-candidate audit. |

These provisional counts should not be used as final published counts until the
manual review queue below is resolved.

## Pre-Migration-to-New Mapping

| pre-migration label | count | proposed primary | required secondary tags | ambiguity and evidence required |
| --- | ---: | --- | --- | --- |
| `source_bug` | 167 | `source_bug` | Add mechanisms such as `bounds_check`, `nullability`, `stack_safety`, `helper_contract`, `reference_lifetime`, `dynptr_lifecycle`, `pointer_provenance`, `scalar_range`. | Mostly stable. Review low-confidence cases separately, but they are not part of the orthogonality blocker. |
| `lowering_artifact` | 47 | `lowering_artifact` only with strict evidence; otherwise `source_bug` or `environment_or_configuration`. | `scalar_range`, `pointer_provenance`, `stack_layout`, `cfg_join_widening`, `spill_reload_loss`, `proof_established_then_lost`, `compiler_flags` where appropriate. | High-value but fragile. Pre-migration confidence is only high for 4 cases, medium for 40, and low for 3. Require proof-loss or equivalent-lowering evidence before preserving this class. |
| `env_mismatch` | 13 | `environment_or_configuration` | `helper_contract`, `program_type_capability`, `kernel_capability`, `context_access`, `btf_metadata`, `loader_relocation`, `build_metadata`. | Review each case to distinguish true environment/configuration mismatch from source misuse of helper arguments. |
| `verifier_limit` | 4 | `verifier_limit` | `analysis_budget`, `loop_bound`, `combined_stack_budget`, `verifier_budget`, optionally `stack_safety`. | Review source-triggered stack/loop cases. Direct out-of-bounds stack access should become `source_bug`; combined-stack budget should remain `verifier_limit`. |
| `stack_safety` | 3 | Usually `source_bug` | `stack_safety`, `stack_bounds`, `large_stack_object`, `move_to_map_storage`. | Not a primary class. These three pre-migration cases are direct stack-region violations and should likely map to `source_bug`, not `verifier_limit`. |
| `build_configuration` | 1 | `environment_or_configuration` | `build_config`, `compiler_flags`, `unsupported_opcode`. | Not a primary class. Treat as configuration unless evidence shows a normal intended lowering artifact. |

## Manual Review Queue

### Blocking Review Before Automated Migration

These 24 cases were manually reviewed before the metadata migration changed
primary classes. They were either non-orthogonal top-level labels,
small classes where the source/environment/verifier boundary is easy to get
wrong, or low-confidence lowering artifacts.

Pre-migration `stack_safety` cases:

- `github-commit-cilium-31a01b994f8b`
- `github-commit-cilium-99ac9998471f`
- `github-commit-cilium-bbf57970f552`

Pre-migration `build_configuration` cases:

- `stackoverflow-70392721`

Pre-migration `env_mismatch` cases:

- `github-aya-rs-aya-1233`
- `github-aya-rs-aya-521`
- `github-cilium-cilium-35182`
- `github-commit-cilium-7f2c0f69373b`
- `kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly-cgroup-skb-ingress-61688196`
- `kernel-selftest-dynptr-fail-skb-invalid-ctx-xdp-1a32a21f`
- `kernel-selftest-dynptr-fail-xdp-invalid-ctx-raw-tp-e886d43f`
- `kernel-selftest-exceptions-fail-reject-async-callback-throw-tc-a86cf7b1`
- `kernel-selftest-irq-irq-sleepable-global-subprog-indirect-syscall-c96d09ca`
- `kernel-selftest-irq-irq-sleepable-helper-global-subprog-syscall-7d470f89`
- `stackoverflow-62171477`
- `stackoverflow-67402772`
- `stackoverflow-72606055`

Pre-migration `verifier_limit` cases:

- `kernel-selftest-async-stack-depth-async-call-root-check-tc-21513dda`
- `kernel-selftest-async-stack-depth-pseudo-call-check-tc-320d654d`
- `stackoverflow-70841631`
- `stackoverflow-74614706`

Low-confidence `lowering_artifact` cases:

- `stackoverflow-53136145`
- `stackoverflow-70729664`
- `stackoverflow-76637174`

### Lowering Evidence Review

In addition to the three low-confidence lowering artifacts above, the 40
medium-confidence `lowering_artifact` cases should receive explicit evidence
tags before they are used for published claims as lowering artifacts:

- `github-cilium-cilium-41522`
- `github-commit-bcc-42c00adb4181`
- `github-commit-cilium-3740e9db8fef`
- `github-commit-cilium-4853fb153410`
- `github-commit-cilium-489da3e3f924`
- `github-commit-cilium-4bb6b56b5c22`
- `github-commit-cilium-4d36cac2ee63`
- `github-commit-cilium-50c319d0cbfe`
- `github-commit-cilium-514825596e44`
- `github-commit-cilium-7e3115694f03`
- `github-commit-cilium-847014aa62f9`
- `github-commit-cilium-86c904761b39`
- `github-commit-cilium-892316d8df68`
- `github-commit-cilium-9100ffbef979`
- `github-commit-cilium-b4a0fa7425c7`
- `github-iovisor-bcc-5062`
- `github-orangeopensource-p4rt-ovs-5`
- `stackoverflow-60053570`
- `stackoverflow-70750259`
- `stackoverflow-70760516`
- `stackoverflow-70873332`
- `stackoverflow-71522674`
- `stackoverflow-72560675`
- `stackoverflow-72575736`
- `stackoverflow-73088287`
- `stackoverflow-73282201`
- `stackoverflow-73381767`
- `stackoverflow-74178703`
- `stackoverflow-76760635`
- `stackoverflow-77713434`
- `stackoverflow-77762365`
- `stackoverflow-77967675`
- `stackoverflow-78186253`
- `stackoverflow-78196801`
- `stackoverflow-78208591`
- `stackoverflow-78591601`
- `stackoverflow-78599154`
- `stackoverflow-78958420`
- `stackoverflow-79095876`
- `stackoverflow-79485758`

The four high-confidence lowering artifacts may be migrated automatically if
their case notes already contain the strict evidence tags:

- `github-commit-cilium-4dc7d8047caf`
- `github-commit-cilium-8eb389403823`
- `github-commit-cilium-c3b65fce8b84`
- `github-commit-cilium-caf84595d9cb`

## Minimal Metadata Changes

Do not change case source files, replay artifacts, or fix oracles for this
taxonomy cleanup. The metadata migration should be small:

1. Restrict `label.taxonomy_class` to the primary classes:
   `source_bug`, `lowering_artifact`, `environment_or_configuration`,
   `verifier_limit`, `verifier_false_positive`.
2. Rename pre-migration `env_mismatch` labels to `environment_or_configuration`
   after manual review.
3. Replace pre-migration `stack_safety` primary labels with `source_bug` or
   `verifier_limit` based on the decision rules. For the three audited cases,
   the likely target is `source_bug` with `mechanism_tags: [stack_safety,
   stack_bounds, large_stack_object]`.
4. Replace pre-migration `build_configuration` primary labels with
   `environment_or_configuration` and add `mechanism_tags: [build_config,
   compiler_flags]`.
5. Add `label.mechanism_tags` to every migrated case. This is the key field
   that restores orthogonality.
6. Add `label.obligation_ids` where the existing `error_id` maps cleanly to
   the obligation catalog. Multiple obligations should be allowed.
7. Add `label.evidence_tags` or `label.classification_evidence` for every
   `lowering_artifact`, `verifier_limit`, `environment_or_configuration`, and
   future `verifier_false_positive` case.
8. Preserve `label.error_id`, `label.fix_type`, `label.fix_direction`,
   `label.confidence`, and localization fields.

Example target shape:

```yaml
label:
  taxonomy_class: source_bug
  mechanism_tags:
    - stack_safety
    - stack_bounds
  obligation_ids:
    - BPFIX-O023
  error_id: BPFIX-E023
  fix_type: move_to_map_storage
```

For lowering artifacts, require evidence:

```yaml
label:
  taxonomy_class: lowering_artifact
  mechanism_tags:
    - pointer_provenance
    - spill_reload_loss
  evidence_tags:
    - source_check_present
    - proof_established_then_lost
    - accepted_with_equivalent_lowering
```

## Migration Safety Recommendation

It is safe to proceed with a schema/design migration that introduces secondary
tags and the new `environment_or_configuration` class name. It is not safe to
perform a blind automated metadata migration of all 235 cases yet.

Safe automated changes after review setup:

- add the new allowed-class list to validators and documentation;
- add optional `mechanism_tags`, `obligation_ids`, and evidence-tag validation;
- normalize only mechanically obvious labels after manual confirmation:
  `build_configuration` to `environment_or_configuration`, and the three
  pre-migration `stack_safety` cases to `source_bug` if reviewers confirm they are
  direct stack-bound violations.

Unsafe blind changes:

- preserving all 47 pre-migration `lowering_artifact` labels without evidence tags;
- treating all helper or context failures as environment/configuration without
  checking whether they are actually source-level helper contract violations;
- treating all stack-related failures as `verifier_limit`.

## Commands Run

Representative commands used for this audit:

```bash
sed -n '1,240p' bpfix-bench/taxonomy.yaml
sed -n '1,620p' docs/evaluation/legacy-catalogs/error_catalog.yaml
sed -n '1,520p' docs/evaluation/legacy-catalogs/obligation_catalog.yaml
sed -n '1,520p' docs/evaluation/metrics.md
sed -n '1,520p' docs/evaluation/baselines.md
find bpfix-bench/cases -mindepth 2 -maxdepth 2 -name case.yaml | wc -l
git status --short
```

Aggregate label counts were computed with this read-only Python/YAML scan:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml, collections

rows = []
for p in sorted(Path('bpfix-bench/cases').glob('*/case.yaml')):
    d = yaml.safe_load(p.read_text())
    lab = d.get('label') or {}
    rows.append({
        'case_id': d.get('case_id') or p.parent.name,
        'kind': (d.get('source') or {}).get('kind'),
        'tax': lab.get('taxonomy_class'),
        'err': lab.get('error_id'),
        'conf': lab.get('confidence'),
        'fix_type': lab.get('fix_type'),
        'label_source': lab.get('label_source'),
        'terminal': (d.get('capture') or {}).get('terminal_error'),
        'log_quality': (d.get('capture') or {}).get('log_quality'),
        'external_status': (d.get('external_match') or {}).get('status'),
        'reconstruction': (d.get('reproducer') or {}).get('reconstruction'),
        'repair_eligible': (d.get('repair') or {}).get('eligible'),
    })

print('total', len(rows))
for field in ['tax', 'conf', 'label_source', 'kind', 'log_quality',
              'external_status', 'reconstruction', 'repair_eligible']:
    print(field, collections.Counter(r[field] for r in rows))
PY
```
