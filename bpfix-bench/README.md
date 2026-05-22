# bpfix-bench

`bpfix-bench` is the replayable verifier-failure corpus used by BPFix. The only
discovery entry point is `manifest.yaml`. A case belongs in `cases/` only if it
is self-contained and can be rebuilt, loaded, rejected by the local verifier, and
parsed again by the validator.

External Stack Overflow, GitHub issue, and GitHub commit material is archived
under `raw/`. Raw records are audit material and expansion candidates; they are
not part of primary diagnostic metrics unless they have been admitted to
`cases/` and listed in `manifest.yaml`.

## Current Snapshot

`manifest.yaml` lists 235 replayable cases for
`environment_id: kernel-6.15.11-clang-18-log2`.

| source_kind | cases |
| --- | ---: |
| `github_issue` | 18 |
| `github_commit` | 46 |
| `kernel_selftest` | 85 |
| `stackoverflow` | 86 |
| **total** | **235** |

Primary taxonomy labels:

| taxonomy_class | cases |
| --- | ---: |
| `source_bug` | 187 |
| `lowering_artifact` | 24 |
| `environment_or_configuration` | 11 |
| `verifier_false_positive` | 9 |
| `verifier_limit` | 4 |

Raw external audit records:

| source_kind | records |
| --- | ---: |
| `github_commit` | 591 |
| `github_issue` | 31 |
| `stackoverflow` | 114 |
| **total** | **736** |

The raw directory also contains 201 kernel-selftest raw log fixtures under
`raw/kernel_selftests/`.

## Required Validation

Run the validator before treating this checkout as a valid local benchmark:

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

Expected result on a fully provisioned pinned environment:

```text
passed: 235
failed: 0
```

The benchmark is environment-sensitive. A case can be valid on one kernel,
compiler, libbpf, and BTF setup and fail to reproduce on another.

Latest local validation on this checkout:

```text
passed: 150
failed: 85
```

All 85 failures were `kernel_selftest` cases that failed during build because
the host linker could not find `-lbpf`. The admitted Stack Overflow, GitHub
issue, and GitHub commit cases replayed successfully on this host.

## Raw Audit

Regenerate the raw external audit index with:

```bash
python3 tools/sync_external_raw_bench.py --apply
```

`raw/index.yaml` records reproduction status for external raw material, including
`replay_valid`, `attempted_accepted`, `environment_required`,
`missing_source`, `missing_verifier_log`, `not_reconstructable_from_diff`,
`out_of_scope_non_verifier`, and `replay_reject_no_rejected_insn`.
