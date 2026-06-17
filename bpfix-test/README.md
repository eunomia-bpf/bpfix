# BPFix-Test: LLM One-Shot Repair Stress Suite

`bpfix-test/` 是 BPFix 的高难度 LLM 修复测试目录，不是 `bpfix-bench/`
的替代品。

目标问题很窄：

> 给定同一个 eBPF 源码和同一个 verifier reject，LLM 只看 raw verifier
> log 时能否一次生成可工作的修复？把 raw log 换成 BPFix structured
> diagnostic 后，成功率是否显著提高？

当前目录先提供 18 个可运行的 admitted pilot cases。最终 hard suite 的目标是：

- raw-log one-shot 修复成功率低于 30%；
- structured-log one-shot 修复成功率接近 70%；
- 每个 case 的成功必须由同一个可执行 oracle 判定：编译、verifier load、
  `bpftool prog run` 功能返回值都正确。

## 目录约定

每个 case 是 `cases/<case_id>/` 下的一个文件夹，不使用 YAML 配置：

```text
cases/<case_id>/
  README.md
  buggy.bpf.c
  verifier.log
  structured.json
  test.py
```

`buggy.bpf.c` 是给 LLM 的源文件。`verifier.log` 是本地 pinned 环境抓取的
raw verifier log。`structured.json` 是同一份 log 的 BPFix JSON 输出。
`test.py` 是唯一 oracle：候选修复必须通过它。

## Smoke Test

验证 fixtures 和 buggy 程序确实被 verifier 拒绝：

```bash
python3 bpfix-test/tools/run_suite.py --smoke
```

重新抓取 raw log 和 structured diagnostic：

```bash
cargo build -p bpfix
python3 bpfix-test/tools/refresh_case_artifacts.py
```

当前 admitted pilot cases：

| case | bucket | oracle focus |
| --- | --- | --- |
| `alu32_pointer_cookie_001` | proof lifecycle / lowering | packet pointer provenance must survive ALU lowering |
| `xdp_adjust_head_stale_001` | helper side effect / provenance | `bpf_xdp_adjust_head` must remain and UDP/TCP behavior must hold |
| `ringbuf_stack_submit_001` | helper protocol | stack event cannot be submitted as `ringbuf_mem` |
| `ringbuf_missing_null_check_001` | nullable helper result | reserve result must be checked before write/submit |
| `ringbuf_ref_leak_001` | reference lifecycle | every reserved record path must submit or discard |
| `map_value_branch_merge_001` | proof lifecycle / nullable map value | map-value null proof must survive branch merge before value read |
| `map_value_pointer_cookie_001` | proof lifecycle / map-value provenance | map-value pointer cannot be shifted as an integer cookie before field access |
| `ringbuf_pointer_cookie_001` | helper protocol / provenance | ringbuf record pointer cannot be integer-masked before write/submit |
| `xdp_adjust_head_map_value_001` | helper side effect / map value | packet pointers must be reacquired after `bpf_xdp_adjust_head`, while map-value side effects remain correct |
| `map_value_spill_cookie_001` | map-value provenance / packet behavior | map-value pointer cookie repair must preserve map updates and packet decisions |
| `map_value_inline_cookie_001` | source correlation / map-value provenance | inline map lookup and map updates must survive pointer-cookie repair |
| `packet_macro_cookie_001` | source correlation / packet provenance | macro/inline-style parser proof must survive pointer-cookie repair |
| `packet_inline_return_cookie_001` | source correlation / packet provenance | inline parser return value must remain a checked packet pointer |
| `packet_l4_branch_cookie_001` | proof lifecycle / branch merge | UDP/TCP branch-derived L4 pointers must remain verifier-tracked after merge |
| `packet_vlan_cookie_001` | source correlation / packet provenance | optional VLAN parsing and TCP behavior must survive pointer-cookie repair |
| `ringbuf_branch_cookie_001` | helper protocol / branch behavior | branch-derived ringbuf mark must be preserved while removing pointer-cookie arithmetic |
| `ringbuf_two_record_cookie_001` | helper protocol / reference lifecycle | two reserved records, audit submit, and branch-derived marks must survive repair |
| `xdp_adjust_head_ringbuf_001` | helper side effect / ringbuf protocol | ringbuf reserve/submit must remain correct and post-adjust packet parsing must use the new packet layout |

Calibration cases that raw Qwen27B repaired directly are not admitted into this
hard-mode pilot. If they are reintroduced later, they should be treated only as
regression seeds and hardened with additional non-isomorphic obligations first.

## 运行 LLM One-Shot

runner 使用 OpenAI-compatible `/v1/chat/completions` API，兼容 llama.cpp
server。ActPlane 历史配置使用的本地入口是：

```bash
python3 bpfix-test/tools/run_suite.py \
  --mode raw \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M

python3 bpfix-test/tools/run_suite.py \
  --mode structured \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M
```

如果直接用 llama.cpp：

```bash
/home/yunwei37/workspace/llama.cpp-latest/build/bin/llama-server \
  -m /path/to/qwen27b.gguf -c 32768 -ngl 999 \
  --reasoning off --port 18080
```

已发现的本地 Qwen27B GGUF 路径是：

```text
/home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf
```

可以把它传给 runner 记录 provenance：

```bash
python3 bpfix-test/tools/run_suite.py \
  --mode structured \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M \
  --model-path /home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf \
  --llama-cpp-dir /home/yunwei37/workspace/llama.cpp-latest
```

默认 smoke test 不依赖模型。

Structured mode 的 prompt 会显式告诉模型如何消费 BPFix JSON：
`source_span` 是 verifier 拒绝的操作，`related_spans` 是可用的 proof context
而不是 oracle 答案，`required_proof` 和 `help` 是候选源码必须满足的约束。如果
`help` 说明某个操作不能保留或必须重写，候选源码不能把它作为死代码留在程序里。

## 环境要求

当前 pilot oracle 假设：

- Linux x86_64 with BPF enabled;
- `/usr/include/vmlinux.h` 和 libbpf BPF headers 可用；
- `clang` 支持 `-target bpf`；
- `bpftool` 可用；
- 当前用户可以无交互运行 `sudo bpftool` 和 `sudo rm -f /sys/fs/bpf/...`。

可以通过环境变量覆盖工具入口：

```bash
BPFTOOL="sudo bpftool" CLANG=clang PIN_RM="sudo rm -f" \
PIN_MKDIR="sudo mkdir -p" PIN_RM_TREE="sudo rm -rf" \
  python3 bpfix-test/tools/run_suite.py --smoke
```

## 结果口径

一个 case 只有在以下全部成立时才算修复成功：

- 生成的是可编译的完整 BPF C 源文件；
- `bpftool prog load` 成功；
- case 的 `bpftool prog run` 功能返回值全部匹配；
- case 需要 helper/protocol side effect 时，oracle 还会检查 verifier success
  log 中的必要 helper contract proof，例如 ringbuf reserve/submit；
- case 需要 map 初始状态时，oracle 会 pin map、写入测试值，并检查 successful
  verifier log 中的 map-value proof；
- runner 没有给模型提供 reference fix、ground truth label、oracle 源码以外的答案。

详细实验设计见 [design.md](design.md)。当前 pilot 校准结果见
[pilot-results.md](pilot-results.md)。
