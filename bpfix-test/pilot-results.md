# BPFix-Test Pilot Results

Last run: 2026-06-17

This file records calibration results for the current small pilot suite. These
numbers are not paper-ready benchmark results.

## Qwen27B llama.cpp Clean 9-Case Pilot

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
- Cases: 9
- Repository commit: `687828ee38f92600b54dce4c30eb5e86e6821dbf`
- Repository dirty: `false`
- Raw local artifact:
  `/tmp/bpfix-test-qwen27b-clean-9case-after-hint/20260617T025534108607Z-pid447889/raw/summary.json`
  (`9b9e56522f0539dba291da06714ebfac489d84e2e596d6fd0c5702f904318985`)
- Structured local artifact:
  `/tmp/bpfix-test-qwen27b-clean-9case-after-hint/20260617T025649866414Z-pid449956/structured/summary.json`
  (`d9f8524777ccb026a1acba51f56c3dd34a888541b2e54428c5d1fff8591f2464`)

Results:

| mode | passed | total | pass rate |
| --- | ---: | ---: | ---: |
| raw verifier log | 5 | 9 | 55.6% |
| BPFix structured JSON | 9 | 9 | 100.0% |

Raw-mode per-case result:

| case | result |
| --- | --- |
| `alu32_pointer_cookie_001` | fail: candidate preserved pointer-shift inline asm |
| `map_value_branch_merge_001` | pass |
| `map_value_pointer_cookie_001` | fail: candidate still operated on the map-value pointer with verifier-prohibited bitwise arithmetic |
| `ringbuf_missing_null_check_001` | pass |
| `ringbuf_pointer_cookie_001` | fail: candidate still used verifier-prohibited bitwise arithmetic on a ringbuf pointer |
| `ringbuf_ref_leak_001` | pass |
| `ringbuf_stack_submit_001` | pass |
| `xdp_adjust_head_map_value_001` | fail: candidate loaded successfully but parsed the post-adjust packet at the wrong offset, so UDP returned pass instead of drop |
| `xdp_adjust_head_stale_001` | pass |

Structured-mode per-case result:

| case | result |
| --- | --- |
| `alu32_pointer_cookie_001` | pass |
| `map_value_branch_merge_001` | pass |
| `map_value_pointer_cookie_001` | pass |
| `ringbuf_missing_null_check_001` | pass |
| `ringbuf_pointer_cookie_001` | pass |
| `ringbuf_ref_leak_001` | pass |
| `ringbuf_stack_submit_001` | pass |
| `xdp_adjust_head_map_value_001` | pass |
| `xdp_adjust_head_stale_001` | pass |

Interpretation:

- The harness works end to end: prompts are generated, Qwen27B responses are
  extracted, candidates are compiled, loaded, and checked by executable oracles.
- Structured diagnostics now help all four raw-failing pilot cases. The
  ringbuf/map/packet provenance failures need proof-preserving pointer repair,
  and the XDP adjust-head/map-value case needs both verifier proof repair and
  correct post-adjust packet layout.
- The suite is still too easy for the intended hard-suite target. Raw-log
  one-shot success is 55.6%, well above the target `<30%`.
- The 9-case result is useful engineering evidence for BPFix diagnostic UX, but
  it is not enough for a paper claim. The suite needs more non-isomorphic hard
  cases, repeated runs or more model seeds, and a larger admitted set.

Hardening gate:

- Do not claim `bpfix-test` meets the benchmark goal until a larger admitted
  suite drives raw-log one-shot below 30% under the same model/config.
- Next cases should combine multiple obligations in one source file: helper
  side effects plus branch merge, ref lifecycle plus nullability, source/BTF
  line ambiguity, and object/helper protocol interactions.
