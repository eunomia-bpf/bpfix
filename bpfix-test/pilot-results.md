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

## Qwen27B llama.cpp Next 4 Challenging Cases

Setup matches the clean 9-case pilot above. This run used the current dirty
working tree after adding four new cases, refining two BPFix diagnostic hints,
and tightening the per-case executable oracles.

- Repository base commit: `f1dd4dfb2c6391329df522db66971fc501944dbd`
- Repository dirty: `true`
- Raw local artifact:
  `/tmp/bpfix-test-qwen27b-next4-oracle-tight/20260617T035110212045Z-pid33195/raw/summary.json`
  (`5f6930ab2a8a4a711384de0e1a46258c0ff5cd9e57cf6d88c586fe45d920c330`)
- Structured local artifact:
  `/tmp/bpfix-test-qwen27b-next4-oracle-tight/20260617T035017111923Z-pid33073/structured/summary.json`
  (`5812b29c40b1b07afa815860188d1d36ac44c9c5186508db68fad2683148d996`)

Results:

| mode | passed | total | pass rate |
| --- | ---: | ---: | ---: |
| raw verifier log | 0 | 4 | 0.0% |
| BPFix structured JSON | 3 | 4 | 75.0% |

Raw-mode per-case result:

| case | result |
| --- | --- |
| `map_value_spill_cookie_001` | fail: candidate changed shift into `&= 0xFFFFFFFF`, still prohibited on a map-value pointer |
| `packet_macro_cookie_001` | fail: candidate changed shift into `&= 0xFFFFFFFF`, still prohibited on a packet pointer |
| `ringbuf_branch_cookie_001` | fail: candidate still used prohibited pointer bitwise arithmetic before ringbuf submit |
| `xdp_adjust_head_ringbuf_001` | fail: candidate loaded but parsed the post-adjust packet as if Ethernet header were still present, so UDP returned pass instead of drop |

Structured-mode per-case result:

| case | result |
| --- | --- |
| `map_value_spill_cookie_001` | pass |
| `packet_macro_cookie_001` | pass |
| `ringbuf_branch_cookie_001` | fail: candidate repaired verifier rejection but only preserved one submitted ringbuf mark, losing the UDP/TCP branch-derived mark distinction |
| `xdp_adjust_head_ringbuf_001` | pass |

Combined pilot status:

| suite | raw pass rate | structured pass rate |
| --- | ---: | ---: |
| clean 9-case pilot | 5/9 = 55.6% | 9/9 = 100.0% |
| next 4 challenging cases | 0/4 = 0.0% | 3/4 = 75.0% |
| combined current pilot | 5/13 = 38.5% | 12/13 = 92.3% |

Interpretation:

- The added cases are meaningfully harder for raw-log one-shot repair while
  mostly remaining solvable from structured BPFix diagnostics.
- The structured improvement is not just label matching: all three passing
  structured candidates compiled, loaded, and passed functional/protocol
  oracles. The tightened oracle also caught one structured failure that lost a
  non-verifier branch side effect.
- The combined pilot still does not meet the hard-suite target because raw
  one-shot is 38.5%, above `<30%`. With raw successes fixed at 5, the suite
  needs at least 17 total admitted cases to fall below 30%, so the next batch
  should add at least four more raw-failing cases and continue improving
  structured diagnostics for branch-side-effect preservation.
