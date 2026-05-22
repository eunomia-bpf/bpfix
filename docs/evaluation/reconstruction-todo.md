# Reconstruction Queue

This file tracks the policy for turning raw external records into strict
`bpfix-bench/cases/` entries. There is no active hand-assigned reconstruction
queue in the maintained project state. Historical batch reports remain under
`docs/tmp/`.

## Current State

`bpfix-bench/raw/index.yaml` contains 736 external raw records. Of those, 150
are `replay_valid` and have been admitted to the replayable corpus. The
remaining records are not benchmark cases.

Non-admitted statuses:

| status | records |
| --- | ---: |
| `replay_reject_no_rejected_insn` | 4 |
| `attempted_accepted` | 32 |
| `environment_required` | 197 |
| `missing_source` | 31 |
| `missing_verifier_log` | 15 |
| `not_reconstructable_from_diff` | 45 |
| `out_of_scope_non_verifier` | 262 |

## Admission Rule

A reconstructed case must contain at least:

```text
bpfix-bench/cases/<case_id>/
  Makefile
  prog.c
  case.yaml
```

and must pass local replay:

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

During case development, the individual case should also build and replay with
its own `Makefile` commands before being added to `manifest.yaml`.

## Worker Rules

- Do not add a case to `bpfix-bench/manifest.yaml` until its directory is
  self-contained and replay-valid.
- Do not change `raw/index.yaml` without regenerating or auditing the raw index.
- Keep generated object files and replay logs out of version control.
- Record reconstruction rationale in a maintained doc only if the case is being
  admitted or rejected for a durable reason. Use `docs/tmp/` for scratch batch
  notes.

## Good Next Candidates

The strongest future candidates are usually records with:

- a concrete verifier reject log,
- source code or a small enough snippet to reconstruct,
- program type and load command context,
- no dependency on a large project-specific runtime.

Records marked `environment_required`, `missing_source`, or
`missing_verifier_log` need additional evidence before they can become
benchmark cases.
