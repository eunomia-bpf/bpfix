# BPFix-Test 设计：面向 LLM One-Shot eBPF 修复的挑战集

最后更新：2026-06-17
阶段：40-case admitted milestone; first Qwen27B full-suite completed
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

## 论文型 Target Hypothesis

BPFix structured diagnostic improves one-shot LLM repair for hard eBPF verifier
rejects because it exposes verifier proof obligations, helper contracts, and
proof-loss sites that are implicit or misleading in raw verifier logs.

## Claim Ledger

| ID | Claim | Scope | Metric/evidence | Status |
| --- | --- | --- | --- | --- |
| C1 | Raw verifier logs are insufficient for hard one-shot eBPF repair. | 40-case admitted corpus; paper target remains 100 cases. | Qwen27B raw-log one-shot pass rate below 30%. | supported on 40-case run: 9/40 = 22.5% |
| C2 | BPFix structured diagnostics improve repair success. | Same cases, same model, same prompt budget. | Structured-log pass rate near 70% and absolute gain over raw. | partial on 40-case run: 23/40 = 57.5%, +35.0 pp over raw |
| C3 | The benchmark measures working repairs, not label agreement. | All admitted cases. | Compile + verifier load + functional `bpftool prog run` oracle. | implemented for 40/40 |
| C4 | The suite is hard for source-only pattern matching. | Case construction and 40-case raw-log run. | Cases combine hidden proof loss, helper protocol, branch/source correlation, or modern BPF API contracts. | supported for Qwen27B raw-log baseline: 9/40 = 22.5% |

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

最终 hard suite 目标 100 个 case。当前工程 milestone 已经把可运行 admitted corpus
从 18 个扩到 40 个，并用更均衡的 failure mechanism 降低现有 pointer-cookie/lowering
集中度。40-case 的具体 admission gate、实际 admitted list 和 excluded seeds 见
[40-case-plan.md](40-case-plan.md)。

最终 100-case hard suite 配额：

| Bucket | 数量 | 重点 |
| --- | ---: | --- |
| Proof lifecycle hard cases | 40 | proof 建立、被 lowering/merge/ALU32 破坏、final verifier line 误导 |
| Source/object correlation hard cases | 25 | inline、macro、BTF line info、多 section、多 subprog、Rust/Aya 生成名 |
| Modern BPF protocol cases | 25 | dynptr、kfunc、ringbuf/ref lifecycle、iterator、rbtree、timer、sleepable/RCU/lock |
| Environment/config boundary cases | 10 | helper/kfunc unavailable、wrong prog type、attach mismatch、missing BTF |

当前 40-case corpus 由原始 18-case pilot 加 22 个新增 case 组成。本节只保留
原始 18-case pilot 的详细说明；新增 22 个的实际列表和分类分布见
[40-case-plan.md](40-case-plan.md)。

原始 18-case pilot 覆盖：

- `alu32_pointer_cookie_001`：inline asm/ALU 操作破坏 packet pointer proof；
- `xdp_adjust_head_stale_001`：`bpf_xdp_adjust_head()` invalidates old packet
  pointers，final verifier line 只看到后续 scalar dereference；
- `ringbuf_stack_submit_001`：helper contract 需要 `ringbuf_mem`，源码却把 stack
  object 传给 submit；
- `ringbuf_missing_null_check_001`：`bpf_ringbuf_reserve()` 的 nullable
  `ringbuf_mem_or_null` 未检查就写入；
- `ringbuf_ref_leak_001`：reserve 后一个分支提前退出，导致 reference leak。
- `map_value_branch_merge_001`：`bpf_map_lookup_elem()` 返回的 nullable map value
  只在 UDP 分支里证明 non-null，branch merge 后再次读取 map value。
- `map_value_pointer_cookie_001`：map-value pointer 被当作 integer cookie
  做位移后再访问字段；
- `ringbuf_pointer_cookie_001`：ringbuf reserved record 同时满足 helper
  contract 和 pointer provenance，但源码把 record pointer 经整数 cookie 变换后写入
  并 submit；
- `xdp_adjust_head_map_value_001`：`bpf_xdp_adjust_head()` 后必须重新获取 packet
  pointer，同时还要保留 map-value 计数副作用和 drop 配置语义。
- `map_value_spill_cookie_001`：map-value pointer 经过 saved/cookie/shadow
  链路和 inline asm 位移后再访问字段；正确修复必须删除 cookie round trip，
  但保留 map lookup、`seen_packets` 更新和 packet return 语义。
- `map_value_inline_cookie_001`：map lookup 被藏在 inline helper 中，packet
  protocol 决定 map 语义；正确修复必须删除 map-value pointer cookie，同时保留
  nullable map proof、`seen_packets` 更新和 per-test map 配置行为。
- `packet_macro_cookie_001`：packet parser 把 proof 建立藏在 helper-like inline
  结构里，final reject 落在 pointer cookie 位移；正确修复必须保留 UDP DNS
  drop 行为和 truncated-packet pass 行为。
- `packet_inline_return_cookie_001`：inline parser 返回已检查的 UDP header pointer，
  caller 再经过 pointer cookie 访问端口；正确修复必须保留 inline proof chain。
- `packet_l4_branch_cookie_001`：UDP/TCP 两个分支分别建立 L4 pointer proof，merge
  后 pointer cookie 破坏 provenance；正确修复必须保留 UDP DNS 和 TCP TLS 两种行为。
- `packet_vlan_cookie_001`：packet parser 支持 plain Ethernet 和 802.1Q VLAN 两种
  layout，final reject 在 checked TCP pointer cookie；正确修复必须同时保留 VLAN
  和非 VLAN 行为。
- `ringbuf_branch_cookie_001`：UDP/TCP 分支决定 ringbuf mark，reserve 后对
  ringbuf pointer 做整数 cookie 位移；正确修复必须保留 reserve/submit 和
  mark=7/11 的路径语义。
- `ringbuf_two_record_cookie_001`：同一程序 reserve audit record 和 branch-derived
  record，第二个 record 经 pointer cookie 后 submit；正确修复必须保留 audit
  submit、branch-derived mark 写入、两个 distinct submitted refs 和 UDP/TCP return
  语义。由于 verifier success log 可能把 UDP submit 后续路径折叠成 `safe`，oracle
  不把“每个分支 submit 都被完整打印”当成可观察事实。
- `xdp_adjust_head_ringbuf_001`：`bpf_xdp_adjust_head()` invalidates old packet
  pointer，同时 ringbuf record 仍需 submit；正确修复必须理解 positive
  adjust-head 后新 `ctx->data` 已经指向剥掉 Ethernet header 之后的 IP header。

ringbuf oracle 除了 `bpftool prog run` 返回值，还检查 successful verifier log
中的 helper contract proof：reserve 后的 `ringbuf_mem_or_null`、写入的
`ringbuf_mem(ref_obj_id=...)` 与 submit/discard 使用的是同一个 record。这样能防止
删除 ringbuf 逻辑、空 submit、写 A submit B 这类“修复”误过。

map-value oracle 会 pin map、写入测试配置，再用 `bpftool prog run` 检查返回值。
它还会检查 successful verifier log：候选必须保留 map lookup，并在读取
`drop_proto` 前让源寄存器成为 non-null `map_value`。这个检查基于 annotated trace
里的寄存器状态，而不是某一种固定的 verifier 文本行布局。

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

pilot 阶段：

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

## 当前校准状态

2026-06-17 使用本地 llama.cpp + Qwen27B 跑通了 18-case admitted pilot 的同配置
full-suite run：

- raw verifier log：5/18 pass = 27.8%；
- BPFix structured JSON：18/18 pass = 100.0%；
- repository commit：`443358089579bc2836eda0472bd51f2d75bafe27`；
- llama.cpp commit：`57819b8d4b39d893408e51520dff3d47d1ebb757`；
- model：`Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M`；
- temperature：`0.0`，max tokens：`8192`；
- kernel/toolchain：Linux `6.15.11-061511-generic`，clang `18.1.3`，
  bpftool `v7.7.0`，libbpf `v1.7`。

这轮结果说明当前 pilot 已达到设计时的 calibration target：raw-log one-shot 低于
30%，structured-log one-shot 高于接近 70% 的目标线。它也说明 structured diagnostic
的收益不是 label-proxy：每个 pass 都必须编译、verifier load，并通过 per-case
`bpftool prog run` 功能 oracle 和必要的 helper/proof predicate。

这个结果仍然只是 pilot evidence，不是 paper-ready benchmark：

- admitted case 只有 18 个，paper 目标仍是 100 个；
- case 分布仍集中在 pointer-provenance/lowering、ringbuf/helper contract、map-value
  nullability 和 `bpf_xdp_adjust_head()` side effect；
- Qwen27B 同时用于 hard-case admission 和当前评测，存在 calibration bias；
- 还没有 trimmed raw-log baseline、source-only/code-only baseline、跨模型重复 run、
  或独立 reviewer 审核所有 oracle。

## 40-Case Milestone 状态

2026-06-17 已经达到 40/40 admitted cases。当前验证结果：

- `python3 bpfix-test/tools/audit_cases.py`：40/40 pass；
- `python3 bpfix-test/tools/audit_cases.py --smoke`：40/40 pass；
- 40 个 case 都包含源码、raw verifier log、BPFix structured JSON 和可执行
  `test.py` oracle；
- 所有 `structured.json` 都是 supported diagnostic，没有 `unknown`。

当前 40-case corpus 的 structured diagnostic 分布：

| error_id | failure_class | next_action | count |
| --- | --- | --- | ---: |
| `BPFIX-E001` | source_bug | bounds | 4 |
| `BPFIX-E002` | source_bug | null | 5 |
| `BPFIX-E003` | source_bug | bounds | 1 |
| `BPFIX-E003` | source_bug | initialize | 1 |
| `BPFIX-E004` | source_bug | release | 2 |
| `BPFIX-E005` | source_bug | bounds | 3 |
| `BPFIX-E006` | lowering_artifact | provenance | 11 |
| `BPFIX-E008` | source_bug | protocol | 5 |
| `BPFIX-E010` | source_bug | protocol | 1 |
| `BPFIX-E011` | source_bug | provenance | 5 |
| `BPFIX-E012` | source_bug | protocol | 2 |

同日完成了第一轮真实 40-case LLM full-suite：

- raw verifier log：9/40 pass = 22.5%；
- BPFix structured JSON：23/40 pass = 57.5%；
- repository commit：`93f90fbeb39cb66517c970c784942b483102c659`；
- llama.cpp commit：`57819b8d4b39d893408e51520dff3d47d1ebb757`；
- model：`Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M`；
- temperature：`0.0`，max tokens：`8192`；
- server flags：`-c 32768 -ngl 999 --reasoning off --cache-ram 0`。

这个结果支持 C1：40-case raw-log baseline 已经低于 30%。它只部分支持 C2：
structured diagnostic 带来 +35.0 percentage-point 的真实修复提升，但 57.5% 低于
near-70% 目标线。失败主要集中在 dynptr edge cases、stack/helper memory contract、
signed range lower-bound、wrong-base packet checks、map-value proof predicate 和
ringbuf multi-reference lifecycle side effects。

因此当前可以说“40-case corpus 已经构建、通过 verifier/oracle smoke，并完成第一轮
真实 Qwen27B raw/structured repair run”。还不能说“BPFix structured repair 已达到
paper target”；下一步必须提升 diagnostics 或 prompt contract，并补 trimmed raw-log
baseline、跨模型重复和独立 oracle review。
