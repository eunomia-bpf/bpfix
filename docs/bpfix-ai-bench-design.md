# BPFix AI Repair Benchmark 设计

状态：设计稿
日期：2026-06-13

## 定位

`bpfix-ai-bench` 是一个 source-first、single-file、challenging 的 eBPF
verifier repair benchmark。它评估的不是 BPFix 自己的诊断准确率，而是：

> 给 AI agent 一个 verifier reject 的 eBPF 源文件，并可选给它原始
> verifier log，它能不能生成一个源码补丁，使程序重新编译、通过 verifier，
> 并且在 `BPF_PROG_TEST_RUN` 下保持原本应该有的计算结果和返回值？

这和 `bpfix-bench` 是互补关系：

- `bpfix-bench`：真实世界 verifier reject corpus，用来评估 BPFix 对日志的诊断能力。
- `bpfix-ai-bench`：高难度源码修复 benchmark，用来评估 Qwen、Llama、Codex
  等 AI agent 是否真的能修 verifier reject。

这个 benchmark 的准确描述是 challenging and realistic：case 难，是因为它们
覆盖真实 verifier proof failure、compiler lowering ambiguity 和现代 BPF 协议规则，
而不是因为 prompt 故意设陷阱。

## 非目标

- 不从 `bpfix-bench` 的 235 个 case 里再挑 100 个做小 benchmark。
- 不做 log-first diagnostic benchmark。
- 不使用 YAML case config。
- 不维护 `logs/`、`oracle/`、`reference-fixes/` 目录。
- 不用 exact patch match 判分。
- 不把 `error_id` 或解释文本当成最终正确性标准。
- 不把同一个语义 bug 包装成多种日志格式后重复计数。
- 不让每个 case 变成一个完整多文件项目。

## 目录结构

建议使用独立顶层目录：

```text
bpfix-ai-bench/
  README.md
  DESIGN.md
  tools/
    build_case.py
    capture_log.py
    grade_patch.py
    run_suite.py
    run_llama_cpp.py
    summarize.py
  cases/
    proof_lifecycle/
      packet_branch_merge_001/
        prog.bpf.c
      scalar_range_bswap_001/
        prog.bpf.c
    source_object_ambiguity/
      macro_line_many_insns_001/
        prog.bpf.c
    modern_bpf_protocol/
      dynptr_slice_null_001/
        prog.bpf.c
    semantic_preservation_traps/
      constant_return_trap_001/
        prog.bpf.c
  runs/
    .gitignore
```

每个 case 是一个目录，但 checked-in 的核心输入只有一个 `prog.bpf.c`。
case id 就是目录名。case 发现方式是目录遍历：

```bash
find bpfix-ai-bench/cases -name prog.bpf.c
```

构建产物、verifier log、模型 prompt、模型响应、候选 patch、load log 和结果
JSON 都放在 `runs/<run-id>/...`，不进入 case 定义。

## 单文件 Case Contract

每个 `prog.bpf.c` 同时包含三类内容：

1. host runner 可读取的测试规格；
2. 模型允许修改的失败 BPF 程序；
3. 必要的 BPF helper/include/fixture 定义。

不使用 YAML。元数据和测试向量直接写在 C 文件里，用宏暴露给 host runner：

```c
#ifdef BPFAI_HOST_SPEC
#define BPFAI_CASE_ID "packet_branch_merge_001"
#define BPFAI_FAMILY "proof_lifecycle"
#define BPFAI_PROG_TYPE BPFAI_PROG_XDP
#define BPFAI_EXPECT_ORIGINAL_REJECT 1

#define BPFAI_TESTS(X)                                                        \
	X("short_ipv4", BPFAI_RET_XDP_DROP, packet_short_ipv4, 0x00000000)     \
	X("valid_tcp", BPFAI_RET_XDP_PASS, packet_valid_tcp, 0x01020304)       \
	X("valid_udp", BPFAI_RET_XDP_PASS, packet_valid_udp, 0x05060708)

#else

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* BPFAI_EDIT_START */
SEC("xdp")
int prog(struct xdp_md *ctx)
{
	/*
	 * 这里是会触发 verifier reject 的实现。
	 * AI agent 只能修改 BPFAI_EDIT_START / BPFAI_EDIT_END 之间的内容。
	 */
	return XDP_ABORTED;
}
/* BPFAI_EDIT_END */

char _license[] SEC("license") = "GPL";
#endif
```

grader 必须检查补丁只修改 `BPFAI_EDIT_START` 和 `BPFAI_EDIT_END` 之间的区域。
这可以防止模型通过修改 test vector、program type、section name、expected return
来作弊。

如果某个真实修复必须改 map declaration、inline helper 或 wrapper，那么这些代码
也应该放在 editable region 里面。不可编辑区域只保留测试和判分所需的最小内容。

## 正确性 Oracle

最终 oracle 不是 reference patch，而是 BPF 程序的实际行为。

对每个模型生成的 patch，grader 执行：

1. 用 `clang -target bpf -O2 -g` 编译 patched `prog.bpf.c`；
2. 用 libbpf 加载 object，并捕获 verifier 输出；
3. 找到目标 program section/name；
4. 用 `bpf_prog_test_run_opts` 执行所有测试向量；
5. 检查返回值、输出 packet、map value 或 result checksum；
6. 拒绝“通过 verifier 但破坏功能”的补丁。

第一版核心 suite 应优先选择可以稳定用 `BPF_PROG_TEST_RUN` 执行的 program type：

- XDP
- TC / SCHED_CLS
- socket filter
- cgroup skb

tracing-only 的现代 BPF feature 可以晚一点加入。除非 common runner 能给它提供确定性
返回值或 map-result check，否则不要放进第一版 100-case 核心集合。

功能检查至少应该覆盖一种以上结果：

- action return，例如 `XDP_PASS`、`XDP_DROP`、`TC_ACT_OK`、`TC_ACT_SHOT`；
- 输出 packet 长度或 checksum；
- map 中的结果值；
- per-test counter；
- 从 packet bytes 或 map input 计算出的 scalar result。

这些测试要能抓住常见投机修复：

- 把程序改成常量返回；
- 删除出错访问但不保留原计算；
- 改 section 或 program type 绕开 verifier 规则；
- 删除 map、helper 或关键 branch；
- hard-code 可见测试输入。

headline metric 必须是 functional pass rate，而不是 verifier pass rate。

## 输入 Track

同一个 case 可以在不同输入条件下评估模型。

| Track | 模型看到什么 | 评估问题 |
|---|---|---|
| `source-only` | 只看 `prog.bpf.c` | 模型只看源码能不能修？ |
| `source-raw-log` | 源码 + fresh verifier log | 原始 verifier log 对修复帮助多大？ |
| `source-bpfix-text` | 源码 + raw log + BPFix plain text 诊断 | BPFix 的人类可读诊断是否帮助模型修复？ |
| `source-bpfix-json` | 源码 + raw log + BPFix JSON | 结构化诊断是否更适合 agent 消费？ |

所有 track 使用同一个 grader。区别只在 prompt 输入。

默认 prompt 要求模型只输出 unified diff：

```text
You are fixing one eBPF verifier rejection.
Edit only the region between BPFAI_EDIT_START and BPFAI_EDIT_END.
Return a unified diff against prog.bpf.c.
The patch must compile, pass the verifier, and preserve all BPF test behavior.
```

论文主结果建议先报 one-shot。agentic 多轮修复可以作为单独实验：允许最多 `N`
次尝试，并把 compile/load/test failure 反馈给模型。one-shot 和 multi-attempt
不能混在同一张 headline 表里。

## Case 类型和数量

100 个 case 应该按“修复难度”设计，而不是按 `bpfix-bench` 的 taxonomy 采样。

| 类型 | 数量 | 难点 |
|---|---:|---|
| Proof-lifecycle repairs | 45 | source 看起来已经 check 过，但 proof 经过 branch merge、spill/reload、helper clobber、loop widening 或不同 SSA value 后丢失 |
| Source/object ambiguity repairs | 25 | verifier 指向的 instruction 和真正该修的源码位置不一致，涉及 macro、inline、多条 BPF 指令对应同一源码行、subprog 等 |
| Modern BPF protocol repairs | 20 | 修复需要理解 dynptr、kfunc ref、iterator、timer、lock、sleepable、RCU 或 helper contract |
| Semantic-preservation traps | 10 | 很容易用删除逻辑让 verifier 通过，但 BPF test 会要求保留原本 branch 和计算语义 |

environment/config failure 对 BPFix 诊断有价值，但不适合作为第一版 source-patch
benchmark 的主类。除非正确修复确实是单文件源码 patch，并且可以用 BPF test run
验证，否则不应该放进这 100 个。

## 首批 10 个 Pilot Case

第一阶段不要直接冲 100 个。先做 10 个，验证 harness 能同时抓住 verifier failure
和破坏功能的投机 patch。

| Case | 类型 | 难点 |
|---|---|---|
| `packet_branch_merge_001` | proof lifecycle | bounds proof 在一个 branch 建立，merge 后丢失，最终在 packet read 被拒 |
| `map_value_spill_reload_001` | proof lifecycle | map value pointer 已 check，但 spill/reload 后 null/provenance proof 丢失 |
| `scalar_range_bswap_001` | proof lifecycle | byte-swap/mask lowering 导致 scalar range 变宽，影响 pointer arithmetic |
| `loop_carried_widen_001` | proof lifecycle | loop-carried induction value 在 source guard 后仍被 verifier widening |
| `nullable_copy_use_001` | proof lifecycle | null check 作用在一个 pointer copy，用的是另一个 copy |
| `macro_line_many_insns_001` | source/object ambiguity | 一个宏展开成多条 BPF 指令，真正修复点早于 final reject line |
| `inline_subprog_check_use_001` | source/object ambiguity | proof 在 inline helper 里建立，拒绝发生在 caller/subprog 形态里 |
| `dynptr_slice_null_001` | modern protocol | dynptr slice 返回 nullable pointer，proof 在使用前丢失 |
| `kfunc_ref_release_001` | modern protocol | 条件 acquire/release path 违反 reference lifecycle |
| `constant_return_trap_001` | semantic preservation | 常量返回能过 verifier，但 packet/map result test 会失败 |

## Case 准入标准

一个 case 进入 benchmark 前必须满足：

1. 原始 `prog.bpf.c` 在固定环境里会 verifier reject；
2. harness 能 fresh capture 原始 verifier log；
3. admission 阶段存在一个人工维护的正确修复；
4. 修复后能编译、通过 verifier，并通过所有 BPF test vectors；
5. 至少有 3 个测试向量覆盖不同路径或不同计算结果；
6. 常量返回、删除核心逻辑、改 program type 这类 patch 会被测试打掉；
7. 仅凭 terminal verifier line 不容易直接看出正确修法；
8. 和已有 case 的结构不同，不只是变量名或常量改动。

第 3 条只是 admission sanity check。公开 artifact 不需要保存 reference fix。

## 判分状态

每次模型尝试最终落到一个状态：

| 状态 | 含义 |
|---|---|
| `patch_parse_error` | 响应里没有可应用的 unified diff |
| `illegal_edit` | patch 修改了不可编辑区域或非目标文件 |
| `compile_fail` | patched source 不能编译成 BPF object |
| `verifier_reject` | patched object 仍然被 verifier 拒绝 |
| `test_fail` | object 能加载，但 `BPF_PROG_TEST_RUN` 功能测试失败 |
| `pass` | 编译、verifier load、功能测试全部通过 |

辅助指标：

- one-shot pass rate；
- `N` 次尝试内 pass rate；
- compile-pass rate；
- verifier-pass rate；
- verifier-passing patch 里的 functional-pass rate；
- illegal edit rate；
- constant-return/delete-logic failure rate；
- median patch size；
- median wall time；
- input/output token；
- 按 case family 和 prompt track 的成功率。

## Llama.cpp / Qwen 本地运行

参考父目录 `ActPlane` 的做法，BPF repair runner 应该把本地 Qwen 跑成一个
OpenAI-compatible endpoint：

1. 启动 `llama-server`；
2. 等待 `/health` 变为 healthy；
3. runner 用 `http://127.0.0.1:<port>/v1` 调用；
4. 设置 `OPENAI_API_KEY=dummy`；
5. 一次只跑一个 case，减少本地 GPU 显存和并发噪声；
6. 所有 prompt、raw response、patch、log、score 都写入 append-only run 目录。

当前可复用的启动形态：

```bash
/home/yunwei37/workspace/llama.cpp-latest/build/bin/llama-server \
  -m /home/yunwei37/.cache/huggingface/hub/models--DevQuasar--Qwen.Qwen3.6-27B-GGUF/snapshots/b19fa7e8538a1a5f66452eb3b3167e026177be1d/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf \
  --host 127.0.0.1 \
  --port 18080 \
  --device CUDA0 \
  --fit off \
  -ngl all \
  -c 65536 \
  -np 1 \
  --reasoning off \
  --reasoning-format none \
  --no-webui
```

然后 runner 调用：

```bash
OPENAI_API_KEY=dummy \
python3 bpfix-ai-bench/tools/run_llama_cpp.py \
  --api-base http://127.0.0.1:18080/v1 \
  --model openai/Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M.gguf \
  --track source-raw-log \
  --output runs/qwen36-source-raw-log-001
```

默认关闭 reasoning，原因是 patch extraction 更稳定。可以另设 `thinking-on`
model setting，但不要和主结果混在一起。

runner 需要记录：

- llama.cpp binary path 和版本；
- model path 和 SHA256；
- API model name；
- context size；
- generation limit；
- temperature、top-p、top-k；
- reasoning mode；
- prompt track；
- raw request/response。

## Runner Workflow

每个 case、每个 track 的执行流程：

1. 把 case 复制到临时 workdir；
2. 编译并加载原始源码，确认 verifier reject；
3. fresh capture verifier log 到 `runs/<run-id>/<case-id>/original.log`；
4. 根据 track 构造 prompt；
5. 调用模型；
6. 从模型响应中提取 unified diff；
7. 应用 diff 到临时 `prog.bpf.c`；
8. 检查不可编辑区域 hash；
9. 编译、加载、执行 BPF 功能测试；
10. 写入 `runs/<run-id>/<case-id>/result.json`。

checked-in benchmark 保持 source-only。log 是运行产物，不是 case 定义。

## OSDI 风格实验问题

这个 benchmark 应该服务于可证伪的论文 claim。

| 问题 | 实验 | 支撑条件 |
|---|---|---|
| RQ1: eBPF verifier repair 对本地 LLM 是否真的难？ | Qwen/Llama 跑 `source-only` 和 `source-raw-log` | 成功率显著低于普通 coding benchmark repair |
| RQ2: 原始 verifier log 是否足够？ | 比较 `source-only` 和 `source-raw-log` | raw log 有帮助，但 proof lifecycle 和 source/object ambiguity 仍大量失败 |
| RQ3: BPFix 是否帮助 AI repair？ | 比较 `source-raw-log` 和 `source-bpfix-text/json` | BPFix track 提高 functional pass rate，并降低 unsafe workaround rate |
| RQ4: BPFix 哪些机制有用？ | ablate lifecycle spans、object/BTF correlation、structured JSON | 去掉对应机制后，相关 family 成功率下降 |
| RQ5: artifact 是否可复现？ | 固定环境下重建、recapture log、重跑测试 | 100/100 原始 case 按预期 reject；admission repair sanity check 通过 |

这样它不是一个纯 research demo，而是能回答实际用户问题：AI agent 看到 verifier
reject 时，raw log 是否够用？结构化 verifier proof 诊断是否能提高实际修复成功率？

## 可复现环境

第一版 frozen benchmark 需要 pin：

- kernel version 和 config；
- BTF availability；
- `clang`、`llc`、`bpftool`、libbpf 版本；
- architecture；
- 是否需要 root、`CAP_BPF`、`CAP_PERFMON`；
- llama.cpp commit/release；
- Qwen/Llama GGUF 文件 hash；
- 生成 BPFix diagnosis track 时使用的 BPFix commit。

建议两个执行模式：

- `smoke`：只检查 case 结构、宏解析、编译入口，不需要 root；
- `full`：编译、加载、capture verifier log、调用模型、应用 patch、执行
  `BPF_PROG_TEST_RUN`。

## 里程碑

1. 创建 `bpfix-ai-bench/` skeleton 和 common runner。
2. 实现单文件宏 contract 和 editable-region enforcement。
3. 做 5 个 pilot case，确认 constant-return patch 会失败。
4. 加 `run_llama_cpp.py`，复用 ActPlane 风格的本地 Qwen server。
5. 用 Qwen 跑 pilot 的 `source-only` 和 `source-raw-log`。
6. 扩到 20 个 development cases，覆盖四类 family。
7. 加入 BPFix text/JSON prompt tracks。
8. freeze 50 个 case 做内部 paper pilot。
9. freeze 100 个 case 做论文 artifact。
10. 报告按 family 和 track 拆分的 functional pass rate。

## 仍需决定的问题

- test vector 是否暴露给模型。初版建议暴露在同一个源码文件里，但禁止修改。
  如果将来做 leaderboard，可以增加 hidden tests。
- 是否允许多轮 agent repair。论文主结果建议 one-shot，多轮结果单独报告。
- tracing-only modern BPF feature 是否进入前 100。除非 runner 能提供确定性功能测试，
  否则第一版先不放。
- 顶层目录最终叫 `bpfix-ai-bench/` 还是 `bpfix-test/`。如果目标是 AI repair，
  名字最好显式带 AI，避免和 BPFix 自身 regression test 混淆。

## 调研依据

本地 Qwen runner 设计参考了父目录 `ActPlane`：

- `/home/yunwei37/workspace/ActPlane/docs/terminal-bench/run_local_llama_full.py`
  启动 `llama-server`，等待 `/health`，通过 OpenAI-compatible `/v1` 调用，
  单任务顺序执行，并写 append-only JSON 结果。
- `/home/yunwei37/workspace/ActPlane/docs/terminal-bench/README.md`
  记录了本地 Qwen 27B GGUF run shape 和 `OPENAI_API_KEY=dummy` 约定。
- `/home/yunwei37/workspace/ActPlane/docs/eval.md`
  记录了 local llama.cpp provider、model name、context size 和 run provenance
  等元数据。

外部参考：

- llama.cpp `llama-server` 文档：OpenAI-compatible HTTP server、GGUF GPU/CPU
  inference、context-size、GPU offload、reasoning controls。
  <https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md>
- Qwen llama.cpp 文档：Qwen GGUF 可通过 `llama-cli` 和 `llama-server` 本地运行，
  并说明 Qwen3/Qwen3MoE 从 llama.cpp `b5092` 开始支持。
  <https://qwen.readthedocs.io/en/latest/run_locally/llama.cpp.html>
