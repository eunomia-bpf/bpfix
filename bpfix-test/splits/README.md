# BPFix-Test Splits

`dev40.txt` is the current calibration split. It was used while developing
cases, prompts, diagnostics, and oracle checks, so it must not be reported as
the final clean paper benchmark.

`clean60.txt` is reserved for the heldout benchmark. It is intentionally empty
until 60 new cases are admitted. A valid clean split must:

- contain exactly 60 case ids;
- have no overlap with `dev40.txt`;
- contain no duplicates or unknown cases;
- pass `audit_cases.py` for every case;
- pass buggy-reject smoke for every case before any LLM result is collected.

Each split also has a machine-readable manifest:

- `dev40.manifest.json` records that the current 40 cases are calibration data.
- `clean60.manifest.json` is the heldout manifest. It must be frozen before the
  first clean run and must carry per-case source category, bucket, program type,
  independent review status, oracle obligations, and case hashes.

`run_suite.py` treats an explicit empty `--split` as an error unless
`--allow-empty-split` is passed, so an unadmitted clean split cannot silently
fall back to all dev cases.
`audit_splits.py --profile clean60` always compares against `dev40.txt` by case
id, full case hash, and `buggy.bpf.c` hash; `--disallow-overlap` keeps that
comparison explicit in documented commands.

Run the gates:

```bash
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
