# Editor and Agent JSON

Editors and agents should use BPFix JSON instead of scraping the text output:

```bash
bpfix --format json verifier.log > bpfix-diagnostic.json
```

`json-output.sh` is a minimal wrapper. `diagnostic.schema.example.json` is not a
formal JSON Schema yet; it documents the stable field shape expected by
integrations.
