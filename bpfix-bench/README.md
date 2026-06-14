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
python3 bpfix-bench/tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
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
passed: 235
failed: 0
```

The `kernel_selftest` loader builds link against the local
`vendor/libbpf` submodule through `bpfix-bench/libbpf.mk`, so replay does not
depend on a host `libbpf` install for `-lbpf`. The host still needs the normal
replay toolchain dependencies, including clang, bpftool, libelf, zlib, sudo,
kernel BTF, and a compatible kernel.

## Diagnostic Evaluation

Run BPFix over every admitted replay log in the benchmark:

```bash
python3 bpfix-bench/run-bpfix-eval.py --confusion --coverage --reject-fallback
```

The driver builds the Rust `bpfix` CLI by default, reads `manifest.yaml`, and
invokes `bpfix --format json` for each case log through the shared metric
implementation in `docs/evaluation/evaluate_diagnostics.py`. `--reject-fallback`
fails the run if any admitted replay case emits `BPFIX-UNKNOWN`, `BPFIX-E000`,
or `BPFIX-E099`. Use `--bpfix-bin /path/to/bpfix --no-build` to evaluate an
existing binary. The summary also reports BPFix CLI wall-clock time
median/p95/max over the same run; this measures the diagnostic invocation only,
not replay build or loader time.

To include object/CFG attachment coverage, run:

```bash
python3 bpfix-bench/run-bpfix-eval.py --coverage --object-if-available
```

That mode builds `bpfix` with `--features object-analysis` unless
`--bpfix-bin` is supplied, passes each case's checked-in `prog.o`, and reports
parsed object programs, CFG sites, attached verifier states, and non-fatal
object-analysis errors.

## Raw Audit

`raw/index.yaml` records reproduction status for external raw material, including
`replay_valid`, `attempted_accepted`, `environment_required`,
`missing_source`, `missing_verifier_log`, `not_reconstructable_from_diff`,
`out_of_scope_non_verifier`, and `replay_reject_no_rejected_insn`.
