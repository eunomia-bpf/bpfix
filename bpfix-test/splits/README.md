# BPFix-Test Splits

`dev40.txt` is the current calibration split. It was used while developing
cases, prompts, diagnostics, and oracle checks, so it must not be reported as
the final clean paper benchmark.

`real-seed-candidates.txt` is a staging split for real-project seed candidates.
It is useful for repeated audit/smoke runs while the cases are being reviewed,
but it is not a paper benchmark split and must not be reported as clean60.
`real-seed-candidates.manifest.json` records candidate provenance, review,
oracle obligations, and fingerprints so staged cases are pre-audited before
possible clean60 promotion.

`clean60.txt` is reserved for the heldout benchmark. It is intentionally empty
until 60 new cases are admitted. A valid clean split must:

- contain exactly 60 case ids;
- have no overlap with `dev40.txt`;
- contain no duplicates or unknown cases;
- pass `audit_cases.py` for every case;
- pass buggy-reject smoke for every case before any LLM result is collected.

Each split also has a machine-readable manifest:

- `dev40.manifest.json` records that the current 40 cases are calibration data
  and carries frozen full-case and `buggy.bpf.c` fingerprints for contamination
  checks.
- `clean60.manifest.json` is the heldout manifest. It must be frozen before the
  first clean run and must carry per-case source category, bucket, program type,
  independent review status, oracle obligations, provenance, and case hashes.
  It also records the result-blind admission protocol, candidate seed ledger,
  and seed exclusion ledger.

`run_suite.py` treats an explicit empty `--split` as an error unless
`--allow-empty-split` is passed, so an unadmitted clean split cannot silently
fall back to all dev cases.
Auditing `dev40.txt` directly also requires `dev40.manifest.json`, because the
frozen fingerprints are part of the contamination baseline.
`audit_splits.py --profile clean60` always compares against `dev40.txt` by case
id, full case hash, and `buggy.bpf.c` hash. When a compared split has a sibling
manifest, the recorded fingerprints are used as the contamination baseline;
`--disallow-overlap` keeps that comparison explicit in documented commands.
For clean60, the manifest audit also requires machine-readable case review,
provenance, oracle-obligation, selection-protocol, candidate-seed-ledger, and
exclusion-ledger fields.
For candidate and clean60 audits with `--audit-cases`, manifest oracle claims
are cross-checked against `test.py`: `bpftool_prog_run` must have functional
tests, `proof_predicate` must have success predicates, and helper/state
obligations must have success substrings or predicates.
Clean splits are also checked for exact `buggy.bpf.c` source overlap with
`bpfix-bench/cases/**/*.c`.
Clean splits must contain no duplicate `buggy.bpf.c` hashes inside the split
itself. At least 20 cases must be `real_project_seed` cases with structured
upstream project, pinned ref, path, license, and file sha256 provenance.
Candidate/clean60 gates verify each real-project seed against a local upstream
checkout: the commit must exist, the path must resolve at that commit, the file
sha256 must match, and the SPDX license in the upstream file must match
`upstream_license`. The local checkout must also have a git remote matching
`provenance.upstream_project`, and `provenance.source` must be the canonical
GitHub/GitLab blob URL for the same commit and path. By default, upstream repos
are discovered next to this repo; set `BPFIX_TEST_UPSTREAM_ROOT` when they live
elsewhere.
`minimized_upstream_style` is useful for diversity but does not count toward
that real-project minimum.
When auditing clean cases directly, pass the manifest to `audit_cases.py` so
custom, attach/runtime, and environment/config oracles are not forced through
the `bpftool prog run` fixture shape. A case that also declares
`bpftool_prog_run` still has to satisfy the standard `run_case(...)` functional
test contract.

Run the gates:

```bash
python3 bpfix-test/tools/audit_splits.py \
  --split bpfix-test/splits/real-seed-candidates.txt \
  --manifest bpfix-test/splits/real-seed-candidates.manifest.json \
  --profile candidate \
  --disallow-overlap bpfix-test/splits/dev40.txt \
  --audit-cases --smoke

make bpfix-test-real-seed-candidate-gate

python3 bpfix-test/tools/audit_splits.py \
  --split bpfix-test/splits/dev40.txt \
  --manifest bpfix-test/splits/dev40.manifest.json \
  --profile dev \
  --expected-count 40 \
  --audit-cases --smoke

python3 bpfix-test/tools/audit_splits.py \
  --split bpfix-test/splits/clean60.txt \
  --manifest bpfix-test/splits/clean60.manifest.json \
  --profile clean60 \
  --expected-count 60 \
  --disallow-overlap bpfix-test/splits/dev40.txt \
  --audit-cases --smoke
```

Before any paper-grade clean run is reported, also verify the frozen prompt
manifest from a clean worktree. Verification itself must also run from a clean
checkout:

```bash
make bpfix-test-clean60-paper-gate \
  PROMPT_MANIFEST=bpfix-test/splits/clean60.prompts.json
```
