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
- Cases: 6
- Local run artifacts:
  `/tmp/bpfix-test-qwen27b-sixcase-fixed/20260617T013251Z/raw/summary.json`
  (`b6eeb8e3c0c783774a19c6aaaf2d25d8dbb776cbb16594a3074f2ca1865302c1`) and
  `/tmp/bpfix-test-qwen27b-sixcase/20260617T013201Z/structured/summary.json`
  (`b4dba3c82bba288fd899f054e45f2f6db59ee350b1b2c7729bd2c1b6cd662d8b`)

Results:

| mode | passed | total | pass rate |
| --- | ---: | ---: | ---: |
| raw verifier log | 5 | 6 | 83.3% |
| BPFix structured JSON | 5 | 6 | 83.3% |

Raw-mode per-case result:

| case | result |
| --- | --- |
| `alu32_pointer_cookie_001` | fail: candidate preserved pointer-shift inline asm |
| `map_value_branch_merge_001` | pass |
| `ringbuf_missing_null_check_001` | pass |
| `ringbuf_ref_leak_001` | pass |
| `ringbuf_stack_submit_001` | pass |
| `xdp_adjust_head_stale_001` | pass |

Structured-mode per-case result:

| case | result |
| --- | --- |
| `alu32_pointer_cookie_001` | fail: candidate preserved pointer-shift inline asm |
| `map_value_branch_merge_001` | pass |
| `ringbuf_missing_null_check_001` | pass |
| `ringbuf_ref_leak_001` | pass |
| `ringbuf_stack_submit_001` | pass |
| `xdp_adjust_head_stale_001` | pass |

Interpretation:

- The harness works end to end: prompts are generated, Qwen27B responses are
  extracted, candidates are compiled, loaded, and checked by executable oracles.
- The current 6-case pilot is too easy. Raw-log one-shot success is far above
  the intended hard-suite target of `<30%`.
- The structured mode did not improve this pilot under the current Qwen27B
  `--reasoning off` run. That is useful negative evidence: the current
  structured diagnostic for the ALU32/provenance case is not yet repair-useful
  enough, and the pilot is still too small/easy to support a paper claim.
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
