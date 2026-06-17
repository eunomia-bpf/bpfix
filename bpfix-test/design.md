# BPFix-Test 设计：面向 LLM One-Shot eBPF 修复的挑战集

最后更新：2026-06-16
阶段：canary skeleton + 可运行 oracle
仓库路径：`bpfix-test/`

## 定位

`bpfix-bench/` 已经是 verifier 诊断 benchmark：输入是重放 verifier log，
输出是分类、定位和诊断质量。

`bpfix-test/` 不是再做一个小 benchmark。它是一个 source-first、repair-first
的挑战集，用来回答：

> BPFix 的结构化 proof diagnostic 能不能让强 LLM 在真实 eBPF verifier reject
> 上一次生成正确修复？

这里的“正确”不是文本匹配，而是同一份候选源码必须通过可执行 oracle：

1. BPF C 编译成功；
2. verifier load 成功；
3. `bpftool prog run` 的功能返回值正确。

## 论文型 Thesis

BPFix structured diagnostic improves one-shot LLM repair for hard eBPF verifier
rejects because it exposes verifier proof obligations, helper contracts, and
proof-loss sites that are implicit or misleading in raw verifier logs.

## Claim Ledger

| ID | Claim | Scope | Metric/evidence | Status |
| --- | --- | --- | --- | --- |
| C1 | Raw verifier logs are insufficient for hard one-shot eBPF repair. | Synthetic but realistic hard reject cases. | Qwen27B raw-log one-shot pass rate below 30%. | planned |
| C2 | BPFix structured diagnostics improve repair success. | Same cases, same model, same prompt budget. | Structured-log pass rate near 70% and absolute gain over raw. | planned |
| C3 | The benchmark measures working repairs, not label agreement. | All admitted cases. | Compile + verifier load + functional `bpftool prog run` oracle. | canary implemented |
| C4 | The suite is hard for source-only pattern matching. | Case construction. | Cases combine hidden proof loss, helper protocol, branch/source correlation, or modern BPF API contracts. | planned |

## 和 `bpfix-bench` 的区别

| 项目 | `bpfix-bench` | `bpfix-test` |
| --- | --- | --- |
| 目标 | 诊断质量评测 | LLM 一次修复能力压力测试 |
| 输入 | verifier log + case metadata | 源码 + raw log 或源码 + structured diagnostic |
| 输出 | taxonomy/error id/span/action | 完整修复后的 BPF C 源码 |
| oracle | label-proxy metrics | 编译、verifier、功能返回值 |
| 稳定性 | frozen corpus | 可演进 hard suite |
| 数据格式 | YAML case metadata | case 文件夹约定，不用 YAML |

## 系统模型

组件：

- case generator 或人工 curated case；
- raw verifier log；
- BPFix structured JSON；
- LLM one-shot runner；
- per-case executable oracle。

信任边界：

- runner 不读取 reference fix；
- raw 和 structured 两个模式使用同一模型、温度、token budget、timeout；
- 每次 run 保存 git commit/dirty、kernel、clang、bpftool/libbpf、base URL、
  model、temperature、token budget、prompt hash、prompt length、可选 GGUF 路径和
  llama.cpp commit；
- oracle 是唯一成功判定，不能由 LLM 自评。

可观测数据：

- prompt；
- raw response；
- extracted candidate source；
- compile/load/prog-run stdout/stderr；
- pass/fail reason；
- model/config/commit；
- raw 与 structured prompt 的字符数，避免把“结构化更短”误报成纯 proof signal
  改进。

## Case 设计原则

每个 case 应满足：

- 单文件 BPF C，避免把难度藏在 build system；
- buggy 版本必须在 pinned Linux 环境里真实 verifier reject；
- 修复后必须保留原始功能语义；
- raw log 的最后一行不能直接等价于唯一修复动作；
- structured diagnostic 应该暴露 raw log 难以稳定推断的 proof signal；
- 不能把答案放进 case metadata 或 prompt。

不做：

- 不用 YAML 描述标签；
- 不用独立 `oracle/`、`logs/`、`reference-fixes/` 顶层目录；
- 不用人工判断“看起来修好了”；
- 不把 `bpfix-bench` 的 235 个样本重新采样成小集合。

## 能力 Bucket

最终 hard suite 目标 100 个 case：

| Bucket | 数量 | 重点 |
| --- | ---: | --- |
| Proof lifecycle hard cases | 40 | proof 建立、被 lowering/merge/ALU32 破坏、final verifier line 误导 |
| Source/object correlation hard cases | 25 | inline、macro、BTF line info、多 section、多 subprog、Rust/Aya 生成名 |
| Modern BPF protocol cases | 25 | dynptr、kfunc、ringbuf/ref lifecycle、iterator、rbtree、timer、sleepable/RCU/lock |
| Environment/config boundary cases | 10 | helper/kfunc unavailable、wrong prog type、attach mismatch、missing BTF |

canary 先覆盖两个方向：

- `alu32_pointer_cookie_001`：inline asm/ALU 操作破坏 packet pointer proof；
- `ringbuf_stack_submit_001`：helper contract 需要 `ringbuf_mem`，源码却把 stack
  object 传给 submit；oracle 除了 `XDP_PASS` 返回值，还要求成功 verifier log
  中出现 reserve 后的 `ringbuf_mem_or_null` proof 和 submit helper 调用，防止
  删除 ringbuf 逻辑的“修复”误过。

## Experiment Matrix

| Block | Claim | Experiment | Variants | Metric | Oracle | Priority |
| --- | --- | --- | --- | --- | --- | --- |
| B1 | C3 | Canary oracle smoke | buggy should reject | fixture health | `test.py --expect-reject` | must |
| B2 | C1 | Raw one-shot repair | source + raw verifier log | pass rate | per-case `test.py` | must |
| B3 | C2 | Structured one-shot repair | source + BPFix JSON | pass rate, gain over raw | same `test.py` | must |
| B4 | C4 | Difficulty calibration | add/harden cases until raw <30% | raw pass rate | same `test.py` | must |

## Runner 协议

Prompt 输入：

- `buggy.bpf.c`；
- raw 模式：`verifier.log`；
- structured 模式：`structured.json`；
- 固定系统提示：只输出完整替换后的 C 源码，不解释。

Prompt 禁止：

- reference fix；
- label taxonomy；
- oracle expected return values；
- 多轮反馈。

模型调用：

- OpenAI-compatible `/v1/chat/completions`；
- 默认温度 `0.0`；
- 默认模型名兼容 ActPlane 历史配置：`Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M`；
- base URL 默认 `http://127.0.0.1:18080/v1`。
- `--model-path`、`--model-sha256`、`--llama-cpp-dir` 用于记录 GGUF 和
  llama.cpp provenance；不传时结果会显式记录为空。

结果：

- `candidate.bpf.c`；
- `response.txt`；
- `result.json`；
- suite summary。

## 验收门槛

canary 阶段：

- `python3 bpfix-test/tools/run_suite.py --smoke` 通过；
- `python3 bpfix-test/tools/refresh_case_artifacts.py` 能重抓 raw/structured；
- runner 能生成 raw/structured prompt；
- runner 能在有 llama.cpp server 时发起 one-shot 修复并用 oracle 判定。

paper 阶段：

- 至少 100 个 admitted cases；
- Qwen27B raw-log one-shot pass rate < 30%；
- 同一模型 structured-log pass rate 接近 70%；
- 每个 case 至少有一次独立 reviewer 审核：bug 是否真实、修复 oracle 是否覆盖功能；
- 报告 prompt budget、temperature、prompt length、model digest 或明确未记录、
  llama.cpp commit、kernel/toolchain 版本；
- 增加 trimmed raw-log baseline，避免把 structured 提升完全归因于压缩日志。

## 失败解释

如果 raw-log 成功率高于 30%，说明 case 不够难，不能声称 structured diagnostic
显著帮忙；应增加 proof lifecycle/source correlation/modern protocol 组合难度。

如果 structured-log 达不到明显提升，可能意味着：

- BPFix 输出还不够接近 repair-useful proof obligation；
- prompt 没有把 structured fields 转成修复约束；
- case 难度依赖领域知识而不是 verifier proof signal；
- oracle 太窄或 case 修复空间过宽。

这些结果都应保留，不能只筛选 structured 成功的 case。
