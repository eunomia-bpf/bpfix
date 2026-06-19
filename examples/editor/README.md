# Editor and Agent Diagnostics

Editors and agents should consume BPFix's plain-text diagnostic as the stable
handoff format:

```bash
bpfix verifier.log > bpfix-diagnostic.txt
```

`write-diagnostic.sh` is a minimal wrapper for tools that want a file artifact.
