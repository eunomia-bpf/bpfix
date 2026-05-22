# Benchmark Refactor Status

Status: completed

The legacy mixed evaluation entry points have been replaced by the top-level
`bpfix-bench/` benchmark layout. The maintained discovery entry point is:

```text
bpfix-bench/manifest.yaml
```

A primary diagnostic-evaluation case is eligible only if
`docs/bpfix-py/tools/validate_benchmark.py --replay bpfix-bench` can rebuild it, load it,
recapture the verifier rejection, and parse the resulting log locally.

## Current Result

The current manifest contains 235 replayable verifier-reject cases:

| source_kind | cases |
| --- | ---: |
| `github_issue` | 18 |
| `github_commit` | 46 |
| `kernel_selftest` | 85 |
| `stackoverflow` | 86 |
| **total** | **235** |

Expected validator summary on a fully provisioned pinned environment:

```text
passed: 235
failed: 0
total_cases: 235
```

Latest local validation on this checkout produced:

```text
passed: 150
failed: 85
total_cases: 235
```

All failures were `kernel_selftest` cases whose build failed because the host
linker could not find `-lbpf`. This is an environment provisioning issue, not a
manifest-count change.

## Acceptance Criteria

- `bpfix-bench/manifest.yaml` is the benchmark discovery entry point.
- Each listed case is self-contained under `bpfix-bench/cases/<case_id>/`.
- Each listed case has `case.yaml`, source, and replay commands.
- The validator rejects cases that build but do not reproduce a verifier
  rejection.
- `docs/bpfix-py/tools/evaluate_benchmark.py --benchmark bpfix-bench` consumes the same
  manifest and uses freshly replayed verifier logs.
- Non-primary raw material remains under `bpfix-bench/raw/`.

The benchmark is not considered valid on another host until replay passes again
in that host's kernel/compiler/libbpf/BTF environment.
