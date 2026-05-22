# Raw Backlog Triage

This document explains external raw records under `bpfix-bench/raw/`. Raw
records are audit material and future expansion candidates. Primary diagnostic
claims must use only cases listed in `bpfix-bench/manifest.yaml`, where each
case locally builds and replays to a verifier rejection.

Current raw facts come from `bpfix-bench/raw/index.yaml`.

## Status Definitions

| status | meaning |
| --- | --- |
| `replay_valid` | Reconstructed and admitted to the replayable benchmark. |
| `replay_reject_no_rejected_insn` | Replays to a reject, but the log lacks a parseable rejected instruction index. |
| `attempted_accepted` | The reconstructed program loads successfully in the pinned environment. |
| `environment_required` | Reproduction depends on a larger framework, kernel feature, loader setup, architecture, or runtime environment not captured locally. |
| `missing_source` | Verifier-like evidence exists, but source or harness context is missing. |
| `missing_verifier_log` | Source/context exists, but the raw record lacks a concrete verifier log. |
| `not_reconstructable_from_diff` | A commit/diff exists, but it does not provide enough standalone verifier-failure context to reconstruct a benchmark case. |
| `out_of_scope_non_verifier` | The record is not a verifier-reject benchmark candidate. |

## Current Counts

The current raw index has 736 external records.

| status | records |
| --- | ---: |
| `replay_valid` | 150 |
| `replay_reject_no_rejected_insn` | 4 |
| `attempted_accepted` | 32 |
| `environment_required` | 197 |
| `missing_source` | 31 |
| `missing_verifier_log` | 15 |
| `not_reconstructable_from_diff` | 45 |
| `out_of_scope_non_verifier` | 262 |
| **total** | **736** |

By source:

| source_kind | records |
| --- | ---: |
| `github_commit` | 591 |
| `github_issue` | 31 |
| `stackoverflow` | 114 |
| **total** | **736** |

## Admission Rule

To become a primary benchmark case, a raw record must be converted into a
self-contained directory:

```text
bpfix-bench/cases/<case_id>/
  Makefile
  prog.c
  case.yaml
```

and pass:

```bash
python3 tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60
```

Records marked `environment_required`, `missing_source`, `missing_verifier_log`,
or `not_reconstructable_from_diff` should not be counted as benchmark cases
until those missing pieces are resolved.

## Audit Command

```bash
python3 - <<'PY'
from pathlib import Path
from collections import Counter, defaultdict
import yaml

idx = yaml.safe_load(Path("bpfix-bench/raw/index.yaml").read_text())
print(Counter(e["reproduction_status"] for e in idx["entries"]))
by_source = defaultdict(Counter)
for entry in idx["entries"]:
    by_source[entry["source_kind"]][entry["reproduction_status"]] += 1
for source, counts in sorted(by_source.items()):
    print(source, dict(counts))
PY
```
