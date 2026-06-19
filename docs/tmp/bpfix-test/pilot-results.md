# BPFix-Test Pilot Results

Last run: 2026-06-17

This file records calibration results for the current small pilot suite. These
numbers are not paper-ready benchmark results.

## Qwen27B llama.cpp Full 40-Case Same-Config Run

This is the first real LLM repair run over the admitted 40-case dev/calibration
corpus (`bpfix-test/splits/dev40.txt`). Raw and structured modes were run over
the same case set with the same model, server, temperature, token budget,
runner, kernel, and oracle code. The run uses
llama.cpp with prompt cache disabled because an earlier structured run with
prompt cache enabled crashed the local `llama-server` before producing a suite
summary; that aborted partial run is not counted.

Setup:

- Model: `Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M`
- Model path:
  `/home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf`
- llama.cpp commit: `57819b8d4b39d893408e51520dff3d47d1ebb757`
- GPU: NVIDIA GeForce RTX 5090, 32 GB VRAM
- Server flags: `-c 32768 -ngl 999 --reasoning off --cache-ram 0`
- Runner: `bpfix-test/tools/run_suite.py`
- Temperature: `0.0`
- Max tokens: `8192`
- Cases: 40 (`dev40`, not the clean paper benchmark)
- Repository commit: `93f90fbeb39cb66517c970c784942b483102c659`
- Repository dirty: `false`
- Kernel/toolchain: Linux `6.15.11-061511-generic`, clang `18.1.3`,
  bpftool `v7.7.0`, libbpf `v1.7`
- Raw local artifact:
  `/tmp/bpfix-test-qwen27b-full-40-93f90fb-nocache/20260617T200011916619Z-pid847632/raw/summary.json`
  (`beaddcb0126547a769be689b083a4aac09570f0b0c9324568f4522ab515957db`)
- Structured local artifact:
  `/tmp/bpfix-test-qwen27b-full-40-93f90fb-nocache/20260617T200540551769Z-pid848977/structured/summary.json`
  (`d8f7d46f5681a56564f331ad0b1a85ed416a691386b84bef625895047593b917`)

Results:

| mode | passed | total | pass rate |
| --- | ---: | ---: | ---: |
| raw verifier log | 9 | 40 | 22.5% |
| BPFix structured JSON | 23 | 40 | 57.5% |

Per-case result:

| case | raw | structured |
| --- | --- | --- |
| `alu32_pointer_cookie_001` | fail | pass |
| `dynptr_slice_missing_null_check_001` | fail | fail |
| `dynptr_slice_short_mem_001` | fail | fail |
| `dynptr_slice_stack_buffer_001` | fail | fail |
| `dynptr_stack_copy_001` | fail | fail |
| `dynptr_uninitialized_slice_arg_001` | fail | fail |
| `helper_csum_diff_stack_len_001` | fail | fail |
| `helper_map_arg_stack_001` | fail | fail |
| `map_value_branch_merge_001` | pass | pass |
| `map_value_index_guard_oob_001` | fail | fail |
| `map_value_inline_cookie_001` | fail | pass |
| `map_value_pointer_cookie_001` | fail | pass |
| `map_value_signed_index_001` | fail | fail |
| `map_value_spill_cookie_001` | fail | pass |
| `packet_checked_wrong_base_001` | fail | fail |
| `packet_eth_off_by_one_001` | fail | fail |
| `packet_ihl_udp_undercheck_001` | pass | pass |
| `packet_inline_return_cookie_001` | fail | pass |
| `packet_l4_branch_cookie_001` | fail | pass |
| `packet_macro_cookie_001` | fail | pass |
| `packet_macro_payload_undercheck_001` | pass | pass |
| `packet_vlan_cookie_001` | fail | pass |
| `perf_event_packet_payload_001` | fail | fail |
| `ringbuf_branch_cookie_001` | fail | pass |
| `ringbuf_double_submit_001` | fail | fail |
| `ringbuf_missing_null_check_001` | pass | pass |
| `ringbuf_nested_missing_null_001` | fail | fail |
| `ringbuf_nested_reserve_leak_001` | fail | fail |
| `ringbuf_pointer_cookie_001` | fail | pass |
| `ringbuf_ref_leak_001` | pass | pass |
| `ringbuf_stack_discard_001` | pass | pass |
| `ringbuf_stack_submit_001` | pass | pass |
| `ringbuf_submit_after_discard_001` | fail | fail |
| `ringbuf_two_record_cookie_001` | fail | pass |
| `subprog_adjust_tail_stale_001` | fail | pass |
| `subprog_map_value_null_001` | fail | fail |
| `xdp_adjust_head_map_value_001` | pass | pass |
| `xdp_adjust_head_ringbuf_001` | fail | pass |
| `xdp_adjust_head_stale_001` | pass | pass |
| `xdp_adjust_tail_stale_001` | fail | pass |

Structured-mode failures by oracle stage:

| stage | count | cases |
| --- | ---: | --- |
| compile | 1 | `dynptr_uninitialized_slice_arg_001` |
| functional oracle | 11 | `dynptr_slice_missing_null_check_001`, `dynptr_slice_short_mem_001`, `dynptr_slice_stack_buffer_001`, `dynptr_stack_copy_001`, `helper_csum_diff_stack_len_001`, `map_value_signed_index_001`, `packet_checked_wrong_base_001`, `packet_eth_off_by_one_001`, `perf_event_packet_payload_001`, `ringbuf_double_submit_001`, `subprog_map_value_null_001` |
| helper/proof success predicate | 5 | `helper_map_arg_stack_001`, `map_value_index_guard_oob_001`, `ringbuf_nested_missing_null_001`, `ringbuf_nested_reserve_leak_001`, `ringbuf_submit_after_discard_001` |

Interpretation:

- The dev40 corpus is harder than the 18-case pilot: raw-log one-shot repair
  falls to 9/40 = 22.5%, below the hard-suite target of `<30%`.
- BPFix structured diagnostics still help substantially: 23/40 = 57.5%,
  a +35.0 percentage-point absolute gain over raw and 14 additional working
  repairs under the same oracle.
- The structured result does not meet the earlier near-70% target. The failures
  are real candidate failures, not model-call failures: 11 lose functional edge
  cases, 5 lose helper/proof side effects checked by success predicates, and 1
  fails to compile.
- The next engineering target is not to curate easier cases or report dev40 as
  the paper benchmark. It is to improve BPFix repair-useful diagnostics for
  dynptr short/nullable behavior, stack helper memory contracts, signed range
  lower bounds, wrong-base packet checks, map-value proof predicates, and
  ringbuf multi-reference lifecycle obligations, then build the separate
  `clean60` heldout split.

## Qwen27B llama.cpp Full 18-Case Same-Config Pilot

This is the current calibration result for the admitted 18-case pilot. Unlike
the historical roll-up below, raw and structured modes were run over the same
case set with the same model, server, temperature, token budget, runner, kernel,
and oracle code.

Setup:

- Model: `Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M`
- Model path:
  `/home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf`
- llama.cpp commit: `57819b8d4b39d893408e51520dff3d47d1ebb757`
- GPU: NVIDIA GeForce RTX 5090, 32 GB VRAM
- Server flags: `-c 32768 -ngl 999 --reasoning off`
- Runner: `bpfix-test/tools/run_suite.py`
- Temperature: `0.0`
- Max tokens: `8192`
- Cases: 18
- Repository commit: `443358089579bc2836eda0472bd51f2d75bafe27`
- Repository dirty: `false`
- Kernel/toolchain: Linux `6.15.11-061511-generic`, clang `18.1.3`,
  bpftool `v7.7.0`, libbpf `v1.7`
- Raw local artifact:
  `/tmp/bpfix-test-qwen27b-full-18-same-config-4433580/20260617T050654449230Z-pid64558/raw/summary.json`
  (`2aeeed7427552d17aec88e59717d06c614aa8e87be2b73db9560a67f9be542a7`)
- Structured local artifact:
  `/tmp/bpfix-test-qwen27b-full-18-same-config-4433580/20260617T051002605195Z-pid64952/structured/summary.json`
  (`e806f16c437b939a1bb01be93f6cedabf1f14024a523c2ea752b35aee00b96db`)

Results:

| mode | passed | total | pass rate |
| --- | ---: | ---: | ---: |
| raw verifier log | 5 | 18 | 27.8% |
| BPFix structured JSON | 18 | 18 | 100.0% |

Per-case result:

| case | raw | structured |
| --- | --- | --- |
| `alu32_pointer_cookie_001` | fail | pass |
| `map_value_branch_merge_001` | pass | pass |
| `map_value_inline_cookie_001` | fail | pass |
| `map_value_pointer_cookie_001` | fail | pass |
| `map_value_spill_cookie_001` | fail | pass |
| `packet_inline_return_cookie_001` | fail | pass |
| `packet_l4_branch_cookie_001` | fail | pass |
| `packet_macro_cookie_001` | fail | pass |
| `packet_vlan_cookie_001` | fail | pass |
| `ringbuf_branch_cookie_001` | fail | pass |
| `ringbuf_missing_null_check_001` | pass | pass |
| `ringbuf_pointer_cookie_001` | fail | pass |
| `ringbuf_ref_leak_001` | pass | pass |
| `ringbuf_stack_submit_001` | pass | pass |
| `ringbuf_two_record_cookie_001` | fail | pass |
| `xdp_adjust_head_map_value_001` | fail | pass |
| `xdp_adjust_head_ringbuf_001` | fail | pass |
| `xdp_adjust_head_stale_001` | pass | pass |

Interpretation:

- The 18-case pilot now meets the calibration target for this model/config:
  raw verifier log one-shot repair is below 30%, while BPFix structured JSON is
  above the intended near-70% bar.
- This is evidence that the structured diagnostic is repair-useful in the pilot:
  success is judged by compile, verifier load, and executable packet/helper
  oracles, not by label agreement or text matching.
- The result is still not paper-ready. The suite has only 18 cases, is
  concentrated around pointer-provenance/lowering and helper-side-effect
  failures, and used Qwen27B both as a calibration model and evaluation model.
  Paper evidence still needs the separate `clean60` heldout split,
  reviewer-audited oracles, trimmed raw-log baselines, repeated runs or
  additional models, and a stronger source-only/code-only comparison.

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

Historical note: this section is retained for provenance. The
`ringbuf_branch_cookie_001` structured failure below was later diagnosed as an
oracle false negative: the old predicate required verifier text to print both
branch constants at the same store site, while the verifier can fold the UDP
successor path into `safe`. The current full-suite run above supersedes this
batch result.

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
| combined intermediate 13-case pilot | 5/13 = 38.5% | 12/13 = 92.3% |

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

## Qwen27B llama.cpp Admitted Next 5 Cases

Setup matches the clean 9-case pilot above, except `--max-tokens 8192` was used.
This run excludes three calibration candidates that raw Qwen27B repaired
directly (`dynptr_slice_cookie_001`, `map_value_two_lookup_cookie_001`, and
`ringbuf_map_cookie_001`). Those are not counted as hard-mode admitted cases.
The recorded artifacts below are from the tightened-oracle rerun after adding
the VLAN IPv4 non-TCP checks and strengthening the two-record ringbuf
predicates.

- Repository base commit: `c3698d11d8988e1251a247824299cfa0a2326385`
- Repository dirty: `true`
- Raw local artifact:
  `/tmp/bpfix-test-qwen27b-admitted-next5-tightened-v3/20260617T044829217928Z-pid60228/raw/summary.json`
  (`ad40887fd3d0112bd19bd3decd63550fd51cb733a7716503f9cafc9e228db06b`)
- Structured local artifact:
  `/tmp/bpfix-test-qwen27b-admitted-next5-tightened-v3/20260617T044927834654Z-pid60324/structured/summary.json`
  (`f2c8be8d20ed82320423fcb24c70367da02a1d6157f8b1cfe974f366f6661e9f`)

Results:

| mode | passed | total | pass rate |
| --- | ---: | ---: | ---: |
| raw verifier log | 0 | 5 | 0.0% |
| BPFix structured JSON | 5 | 5 | 100.0% |

Per-case result:

| case | raw | structured |
| --- | --- | --- |
| `map_value_inline_cookie_001` | fail | pass |
| `packet_inline_return_cookie_001` | fail | pass |
| `packet_l4_branch_cookie_001` | fail | pass |
| `packet_vlan_cookie_001` | fail | pass |
| `ringbuf_two_record_cookie_001` | fail | pass |

Arithmetic roll-up of admitted pilot runs:

| suite | raw pass rate | structured pass rate |
| --- | ---: | ---: |
| clean 9-case pilot | 5/9 = 55.6% | 9/9 = 100.0% |
| next 4 challenging cases | 0/4 = 0.0% | 3/4 = 75.0% |
| admitted next 5 cases | 0/5 = 0.0% | 5/5 = 100.0% |
| arithmetic roll-up, not same-config full-suite run | 5/18 = 27.8% | 17/18 = 94.4% |

Interpretation:

- The arithmetic roll-up reached the raw `<30%` calibration target, but it was
  not a single 18-case run under one max-token configuration. It is superseded
  by the full 18-case same-config run at the top of this file.
- This is still not a paper-ready benchmark result. The suite is small, case
  admission used one model as a difficulty gate, and no trimmed-raw or
  cross-model baseline has been run yet.
- The admitted next-5 batch is intentionally challenging but still concentrated
  around the `PointerShiftDropsProvenance` signal. Treat it as a pilot
  calibration batch, not evidence of broad protocol/source-correlation
  coverage.
- The explicit calibration exclusions are important: they prevent raw-pass
  candidates from being silently counted as hard cases or silently discarded
  without provenance.
