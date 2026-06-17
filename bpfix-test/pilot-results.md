# BPFix-Test Pilot Results

Last run: 2026-06-17

This file records calibration results for the current small pilot suite. These
numbers are not paper-ready benchmark results.

## Qwen27B llama.cpp Clean 7-Case Pilot

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
- Repository commit: `7942646a6ca0dfdaf5a9cce7ed7315584290457e`
- Repository dirty: `false`
- Local run artifacts:
  `/tmp/bpfix-test-qwen27b-map-pointer-oracle-tight/20260617T021645041329Z-pid382118/raw/summary.json`
  (`9f2265a0dc4c21ba6d5377eb54354237bed1acb69bf9b57ccf06a7349286f6cc`) and
  `/tmp/bpfix-test-qwen27b-map-pointer-oracle-tight/20260617T021740411977Z-pid382364/structured/summary.json`
  (`8aab715fcdc6041162af4518f87ea48817520f6e0294d3d7112acddc41b8b174`)

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
  lookup, removed pointer-as-integer arithmetic, updated `seen_packets`, and
  passed the executable map-value oracle. This supports the direction, but the
  suite still needs many more non-isomorphic hard cases before it can support a
  benchmark claim.
- Adding `map_value_branch_merge_001` exposed an oracle bug: the first map-value
  predicate accepted only one verifier text layout and rejected a correct
  candidate where the non-null `map_value` proof appeared on the preceding
  branch-state line. The predicate now tracks annotated-trace register state
  before the load instruction.
- The oracle was hardened after review with negative probes for fixed-offset
  packet parsing, stale scalar protocol reads, path-local ringbuf writes, and
  wrong ringbuf payload values. Those probes fail under the current tests; the
  ringbuf predicates also require offset `+0` writes into a 4-byte reserved
  record, the map-value cases require real map lookup and non-null map-value
  load evidence, `map_value_pointer_cookie_001` additionally requires offset
  `+4` map-value load/store evidence for the `seen_packets` update, and the XDP
  adjust-head case requires helper delta `14`.

Hardening gate:

- Do not claim `bpfix-test` meets the benchmark goal until a larger admitted
  suite drives raw-log one-shot below 30% under the same model/config.
- Next cases should combine multiple obligations in one source file: helper
  side effects plus branch merge, ref lifecycle plus nullability, source/BTF
  line ambiguity, and object/helper protocol interactions.

## Qwen27B Two-Case Combo Add-On

This add-on was run before committing the two new cases, so repository dirty is
`true`. Treat it as development calibration only, not as a clean benchmark run.

Setup differences from the clean pilot:

- Cases: `ringbuf_pointer_cookie_001`, `xdp_adjust_head_map_value_001`
- Repository commit: `8428b1d409c483311073d9068236eecf0fcbf512`
- Repository dirty: `true`
- Raw local artifact:
  `/tmp/bpfix-test-qwen27b-new-combo/20260617T024313880933Z-pid440630/raw/summary.json`
  (`05e8dd8dd3e2a49f5d51d1d0520712b840265df7eebc0eed9b93f147f710e61c`)
- Structured local artifact:
  `/tmp/bpfix-test-qwen27b-new-combo/20260617T024341228470Z-pid440910/structured/summary.json`
  (`d6c2091c094a9fe78d6cabb437e87fb47bcc82c5d8361ea8e508b31421cc8794`)

Results:

| mode | passed | total | pass rate |
| --- | ---: | ---: | ---: |
| raw verifier log | 0 | 2 | 0.0% |
| BPFix structured JSON | 2 | 2 | 100.0% |

Raw-mode failures:

| case | failure |
| --- | --- |
| `ringbuf_pointer_cookie_001` | candidate replaced the pointer shift with another verifier-prohibited bitwise operation on a ringbuf pointer |
| `xdp_adjust_head_map_value_001` | candidate loaded successfully but parsed the post-adjust packet at the wrong offset, so UDP returned pass instead of drop |

Structured-mode result:

| case | result |
| --- | --- |
| `ringbuf_pointer_cookie_001` | pass |
| `xdp_adjust_head_map_value_001` | pass |

Indicative combined calibration:

| source | raw | structured |
| --- | ---: | ---: |
| clean 7-case pilot | 5/7 | 7/7 |
| dirty two-case add-on | 0/2 | 2/2 |
| combined development signal | 5/9 | 9/9 |

The new cases are useful because raw mode fails in two different ways: one
candidate remains verifier-invalid, and the other becomes verifier-valid but
functionally wrong. The combined raw rate is still 55.6%, so the suite remains
too easy for the target `<30%` raw-log threshold.
