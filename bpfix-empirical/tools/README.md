# bpfix-empirical Tools

These scripts maintain the replayable empirical corpus. They are not a Python
implementation of BPFix and are not part of the public diagnostic CLI.

- `validate_empirical.py` rebuilds and reloads admitted `bpfix-empirical` cases,
  then checks that the fresh verifier rejection matches each case record. It
  expands `manifest.yaml.case_defaults` before replay so case files do not
  repeat fixed paths and commands. It also rejects redundant
  `label.rejected_insn_idx` fields and non-null
  `label.root_cause_insn_idx` values that are not present in the stored local
  replay verifier log. When a `root_cause_line` has source comments in the local
  replay log, the root instruction must point at one of those source-backed PCs,
  or at the immediately preceding PC when line info lags the semantic operation.
  For migrated external cases, it also checks high-risk
  legacy-numbering shadows where a root PC still equals the raw-log rejected PC
  after the replay rejected PC changed.
- `empirical_metadata.py` contains the shared manifest-default expansion used by
  the validator and diagnostic evaluation scripts.
- `replay_case.py` contains the shared build/load/log parsing helper used by
  the validator.

Normal users should run the Rust CLI on a verifier/build/load log:

```bash
bpfix verifier.log
```

Diagnostic evaluation uses the empirical corpus driver at the corpus root:

```bash
python3 bpfix-empirical/run-bpfix-eval.py --confusion --reject-fallback
```
