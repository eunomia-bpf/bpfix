# Editor and Agent JSON

Editors and agents should use BPFix JSON instead of scraping the text output:

```bash
bpfix --format json verifier.log > bpfix-diagnostic.json
```

`json-output.sh` is a minimal wrapper. `diagnostic.schema.example.json` is a
copyable example payload. The formal JSON Schema for the same contract lives at
`docs/evaluation/diagnostic.schema.json`.
