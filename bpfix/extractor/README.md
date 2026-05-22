# bpfix/extractor

Verifier-log diagnostic pipeline for BPFix. The entry point is
`bpfix.extractor.pipeline.generate_diagnostic()`, which takes a raw LOG_LEVEL2 verifier log and
returns text plus structured JSON.

## Flow

```text
raw verifier log
  -> log_parser.py
  -> trace_parser.py
  -> engine/ opcode safety, monitoring, CFG, dataflow, slicing
  -> source_correlator.py
  -> renderer.py
```

## Files

| Path | Role |
|------|------|
| `pipeline.py` | Top-level orchestration and diagnostic assembly |
| `log_parser.py` | Terminal verifier error and catalog classification |
| `trace_parser.py` | Public LOG_LEVEL2 trace parser |
| `trace_parser_impl.py` | Trace parser implementation |
| `engine/` | CFG, control dependence, dataflow, slicing, monitor, opcode safety |
| `source_correlator.py` | Map proof events to source or bytecode spans |
| `renderer.py` | Render text and schema-compatible JSON |
| `reject_info.py` | Specialized verifier reject extraction |
| `bpftool_parser.py` | Parse `bpftool prog dump xlated linum` output |
