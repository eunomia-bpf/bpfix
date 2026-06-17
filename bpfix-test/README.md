# BPFix-Test: LLM One-Shot Repair Stress Suite

`bpfix-test/` 是 BPFix 的高难度 LLM 修复测试目录，不是 `bpfix-bench/`
的替代品。

目标问题很窄：

> 给定同一个 eBPF 源码和同一个 verifier reject，LLM 只看 raw verifier
> log 时能否一次生成可工作的修复？把 raw log 换成 BPFix structured
> diagnostic 后，成功率是否显著提高？

当前目录已经提供 40 个可运行的 admitted cases，但它们属于 `dev40`
calibration split：这些 case 已经参与过 prompt、diagnostic 和 oracle 开发，不能
作为论文主 benchmark。paper-grade 目标是新的 `clean60` heldout split，必须由 60
个不和 `dev40` 重叠的 case 组成。clean split 在 admitted 前必须保持为空并让审计
失败，避免误报。

dev/hard-suite calibration 目标是：

- raw-log one-shot 修复成功率低于 30%；
- structured-log one-shot 修复成功率接近 70%；
- 每个 case 的成功必须由同一个可执行 oracle 判定：编译、verifier load、
  `bpftool prog run` 功能返回值都正确。

`dev40` 的同配置 Qwen27B/llama.cpp 结果是 raw `9/40`
和 structured `23/40`；完整配置、artifact hash 和 per-case 表见
`pilot-results.md`。这是真实 LLM repair run：每个 pass 都经过编译、verifier
load 和 `bpftool prog run` oracle，但它仍是 dev/calibration evidence。18-case
pilot 的历史结果 raw `5/18` 和 structured `18/18` 仍保留在
`pilot-results.md`，报告时必须分开。
具体配额、admission gate、actual admitted list 和 excluded seeds 见
[40-case-plan.md](40-case-plan.md)。

`clean60` 的无污染 benchmark 协议见 [clean60.md](clean60.md)。

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

检查 case 文件结构、structured JSON、oracle prompt 是否泄露 `test.py` 信息：

```bash
python3 bpfix-test/tools/audit_cases.py
```

验证 fixtures 和 buggy 程序确实被 verifier 拒绝：

```bash
python3 bpfix-test/tools/run_suite.py --smoke
```

也可以把两者合并为逐 case 的真实 audit：

```bash
python3 bpfix-test/tools/audit_cases.py --smoke
```

检查 split 和污染规则：

```bash
make bpfix-test-dev40-gate

# Expected to fail until 60 heldout cases are admitted.
make bpfix-test-clean60-gate
```

等价的底层命令是：

```bash
python3 bpfix-test/tools/audit_splits.py \
  --split bpfix-test/splits/dev40.txt \
  --manifest bpfix-test/splits/dev40.manifest.json \
  --profile dev \
  --expected-count 40 \
  --audit-cases --smoke

python3 bpfix-test/tools/audit_splits.py \
  --split bpfix-test/splits/clean60.txt \
  --manifest bpfix-test/splits/clean60.manifest.json \
  --profile clean60 \
  --expected-count 60 \
  --disallow-overlap bpfix-test/splits/dev40.txt \
  --audit-cases --smoke
```

第二个命令在 `clean60` 填满前应该失败；runner 直接使用空 `--split` 也会失败，
不会退回到全量 discovered cases。这是保护主 benchmark 不被 dev cases 污染的
gate。Manifest 审计还会检查 split/manifest 一致性、clean freeze 状态、source
category、bucket、program type、review status、oracle obligation 和 case hash。

生成并验证 frozen prompt manifest：

```bash
python3 bpfix-test/tools/prompt_manifest.py \
  --split bpfix-test/splits/clean60.txt \
  --expected-count 60 \
  --output bpfix-test/splits/clean60.prompts.json

python3 bpfix-test/tools/prompt_manifest.py \
  --split bpfix-test/splits/clean60.txt \
  --expected-count 60 \
  --verify bpfix-test/splits/clean60.prompts.json
```

`*.prompts.json` 是被 gitignore 的本地/发布 artifact；报告时记录它的路径和 hash，
但不要把它变成导致 clean run `git dirty` 的工作区文件。

检查 LLM 结果矩阵是否可报告：

```bash
python3 bpfix-test/tools/audit_results.py \
  --split bpfix-test/splits/clean60.txt \
  --expected-count 60 \
  --prompt-manifest bpfix-test/splits/clean60.prompts.json \
  --required-mode source-only \
  --required-mode raw \
  --required-mode trimmed-raw \
  --required-mode structured \
  /path/to/source-only/summary.json \
  /path/to/raw/summary.json \
  /path/to/trimmed-raw/summary.json \
  /path/to/structured/summary.json
```

这个 result gate 会拒绝混用不同 split、缺 baseline、case 顺序不一致、prompt hash
和 frozen manifest 不一致、不同模型或工具链配置、缺模型 digest、dirty worktree、
prompt-only dry run、以及没有 `failure_stage` 的失败结果。正式 clean60 报数必须
先通过 admission gate，再通过 prompt gate 和 result gate。

重新抓取 raw log 和 structured diagnostic：

```bash
cargo build -p bpfix
python3 bpfix-test/tools/refresh_case_artifacts.py
```

原始 18-case admitted pilot：

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
  --split bpfix-test/splits/dev40.txt \
  --expected-count 40 \
  --mode raw \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M

python3 bpfix-test/tools/run_suite.py \
  --split bpfix-test/splits/dev40.txt \
  --expected-count 40 \
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
  --split bpfix-test/splits/dev40.txt \
  --expected-count 40 \
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
`--case` 只用于单 case debug，不能和 `--split` 混用；正式结果必须由 split 文件
决定 denominator。

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
