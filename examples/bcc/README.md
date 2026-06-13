# BCC

Use this when a Python/BCC tool fails while constructing or loading a
`BPF(...)` program.

The shell path is usually enough:

```bash
python3 tool.py 2>&1 | tee verifier.log
bpfix verifier.log
```

`tool-snippet.py` shows a Python-side pattern that writes `verifier.log` and
optionally invokes BPFix. This is useful when the tool is already catching
exceptions and printing a custom error.
