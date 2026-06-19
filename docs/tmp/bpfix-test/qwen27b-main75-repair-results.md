# Qwen 27B main75 Repair Results

Date: 2026-06-19

Suite: `bpfix-test/splits/main.txt`, 75 cases.

Model server:

```bash
/home/yunwei37/workspace/llama.cpp-latest/build/bin/llama-server \
  -m /home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf \
  -c 65536 \
  --port 18080 \
  --host 127.0.0.1 \
  --jinja \
  --no-webui
```

Runner settings:

- model: `Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M`
- temperature: `0`
- max tokens: `8192`
- timeout: `900`
- oracle: each case's `test.py`
- repair success: candidate compiles, loads, and passes all functional/proof checks

## Results

| Prompt mode | Attempts | Passed | Rate |
| --- | ---: | ---: | ---: |
| raw verifier log | 1 | 48/75 | 64.0% |
| raw verifier log | 2 | 54/75 | 72.0% |
| BPFix plain text | 1 | 66/75 | 88.0% |
| BPFix plain text | 2 | 70/75 | 93.3% |

The raw mode gives the model `buggy.bpf.c` and the original verifier/load log.
The BPFix mode gives the model `buggy.bpf.c` and BPFix plain-text diagnostic
output. No JSON diagnostic mode is used.

Retry mode does not use BPFix unless the prompt mode is `bpfix`; it appends the
previous candidate source and the compile/load/verifier/oracle failure context.

## BPFix One-Shot Failures

Failure stages after one BPFix-assisted attempt:

- `compile`: 1
- `verifier_load`: 3
- `functional_oracle`: 1
- `auxiliary_proof_predicate`: 3
- `oracle`: 1

Failed cases:

- `dynptr_uninitialized_slice_arg_001`: compile
- `helper_map_arg_stack_001`: auxiliary proof predicate
- `map_value_index_guard_oob_001`: auxiliary proof predicate
- `packet_checked_wrong_base_001`: functional oracle
- `ringbuf_nested_missing_null_001`: verifier load
- `rs_bpftime_opensnoop_stack_wrong_prog_type_001`: oracle
- `rs_eunomia_http_doff_copy_bound_001`: verifier load
- `rs_tutorial_dynptr_tc_ref_leak_001`: verifier load
- `rs_tutorial_memleak_free_info_merge_001`: auxiliary proof predicate

## BPFix Retry Failures

Retry rescued four of the nine BPFix one-shot failures:

- `packet_checked_wrong_base_001`
- `ringbuf_nested_missing_null_001`
- `rs_eunomia_http_doff_copy_bound_001`
- `rs_tutorial_memleak_free_info_merge_001`

Remaining failures after retry:

- `dynptr_uninitialized_slice_arg_001`: compile
- `helper_map_arg_stack_001`: auxiliary proof predicate
- `map_value_index_guard_oob_001`: auxiliary proof predicate
- `rs_bpftime_opensnoop_stack_wrong_prog_type_001`: oracle
- `rs_tutorial_dynptr_tc_ref_leak_001`: extract source

## Interpretation

BPFix plain-text diagnostics substantially improve Qwen 27B repair success on
the 75-case suite: +18 cases over raw one-shot and +16 cases over raw with one
retry. The remaining failures are not simple verifier acceptance failures; most
are either source extraction/compile failures or cases where the candidate loads
but does not preserve the required proof/side-effect contract checked by the
oracle.

