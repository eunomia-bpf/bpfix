# bpfix-bench Tools

These scripts maintain the replayable benchmark corpus. They are not a Python
implementation of BPFix and are not part of the public diagnostic CLI.

- `validate_benchmark.py` rebuilds and reloads admitted `bpfix-bench` cases,
  then checks that the fresh verifier rejection matches each case record.
- `replay_case.py` contains the shared build/load/log parsing helper used by
  the validator.

Normal users should run the Rust CLI on a verifier/build/load log:

```bash
bpfix verifier.log
```

Diagnostic evaluation uses the benchmark driver at the corpus root:

```bash
python3 bpfix-bench/run-bpfix-eval.py --confusion --reject-fallback
```
