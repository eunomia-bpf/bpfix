# BPFix-Test Pilot Results

Last run: 2026-06-17

This file records calibration results for the current small pilot suite. These
numbers are not paper-ready benchmark results.

## Qwen27B llama.cpp Pilot

Setup:

- Model: `Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M`
- Model path:
  `/home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf`
- llama.cpp commit: `57819b8d4b39d893408e51520dff3d47d1ebb757`
- GPU: NVIDIA GeForce RTX 5090, 32 GB VRAM
- Server flags: `-c 32768 -ngl 999 --reasoning off`
- Runner: `bpfix-test/tools/run_suite.py`
- Temperature: `0.0`
- Max tokens: `4096`
- Cases: 7
- Local run artifacts:
  `/tmp/bpfix-test-qwen27b-map-pointer/20260617T020452724805Z-pid364640/raw/summary.json`
  (`bdb11615d96455e9330f0b86150837165114834669151f77356788ed91f682f9`) and
  `/tmp/bpfix-test-qwen27b-map-pointer/20260617T020549126477Z-pid364784/structured/summary.json`
  (`bd565fd4a08f4a7455acb92c3310f9598c6c14439d30d2d3e1c176b0bc817caa`)

Results:

| mode | passed | total | pass rate |
| --- | ---: | ---: | ---: |
| raw verifier log | 5 | 7 | 71.4% |
| BPFix structured JSON | 7 | 7 | 100.0% |

Raw-mode per-case result:

| case | result |
| --- | --- |
| `alu32_pointer_cookie_001` | fail: candidate preserved pointer-shift inline asm |
| `map_value_branch_merge_001` | pass |
| `map_value_pointer_cookie_001` | fail: candidate rewrote the shift into a bitwise operation that still operated on the map-value pointer |
| `ringbuf_missing_null_check_001` | pass |
| `ringbuf_ref_leak_001` | pass |
| `ringbuf_stack_submit_001` | pass |
| `xdp_adjust_head_stale_001` | pass |

Structured-mode per-case result:

| case | result |
| --- | --- |
| `alu32_pointer_cookie_001` | pass |
| `map_value_branch_merge_001` | pass |
| `map_value_pointer_cookie_001` | pass |
| `ringbuf_missing_null_check_001` | pass |
| `ringbuf_ref_leak_001` | pass |
| `ringbuf_stack_submit_001` | pass |
| `xdp_adjust_head_stale_001` | pass |

Interpretation:

- The harness works end to end: prompts are generated, Qwen27B responses are
  extracted, candidates are compiled, loaded, and checked by executable oracles.
- The current 7-case pilot is too easy. Raw-log one-shot success is far above
  the intended hard-suite target of `<30%`.
- Structured mode now improves the ALU32/provenance canary: raw mode preserved
  the verifier-rejected pointer-shift inline asm, while structured mode removed
  that operation after the prompt told the model to treat `source_span` and
  `help` as repair constraints. This is useful UX evidence for agents, but it is
  not yet a paper-ready benchmark result because the suite is still only seven
  cases and raw success remains high.
- `map_value_pointer_cookie_001` is the first cross-domain provenance canary:
  raw mode changed the rejected shift into another verifier-prohibited bitwise
  operation on a map-value pointer, while structured mode preserved the map
  lookup, removed pointer-as-integer arithmetic, and passed the executable map
  value oracle. This supports the direction, but the suite still needs many more
  non-isomorphic hard cases before it can support a benchmark claim.
- Adding `map_value_branch_merge_001` exposed an oracle bug: the first map-value
  predicate accepted only one verifier text layout and rejected a correct
  candidate where the non-null `map_value` proof appeared on the preceding
  branch-state line. The predicate now tracks annotated-trace register state
  before the load instruction.
- The oracle was hardened after review with negative probes for fixed-offset
  packet parsing, stale scalar protocol reads, path-local ringbuf writes, and
  wrong ringbuf payload values. Those probes fail under the current tests; the
  ringbuf predicates also require offset `+0` writes into a 4-byte reserved
  record, the map-value case requires a real map lookup and a non-null map-value
  load, and the XDP adjust-head case requires helper delta `14`.

Hardening gate:

- Do not claim `bpfix-test` meets the benchmark goal until a larger admitted
  suite drives raw-log one-shot below 30% under the same model/config.
- Next cases should combine multiple obligations in one source file: helper
  side effects plus branch merge, ref lifecycle plus nullability, source/BTF
  line ambiguity, and object/helper protocol interactions.
