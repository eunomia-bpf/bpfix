# BPFix-Test 设计：面向 LLM One-Shot eBPF 修复的挑战集

最后更新：2026-06-17
阶段：18-case admitted pilot + 可运行 oracle
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
| C1 | Raw verifier logs are insufficient for hard one-shot eBPF repair. | Synthetic but realistic hard reject cases. | Qwen27B raw-log one-shot pass rate below 30%. | planned |
| C2 | BPFix structured diagnostics improve repair success. | Same cases, same model, same prompt budget. | Structured-log pass rate near 70% and absolute gain over raw. | planned |
| C3 | The benchmark measures working repairs, not label agreement. | All admitted cases. | Compile + verifier load + functional `bpftool prog run` oracle. | pilot implemented |
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

当前 admitted pilot 先覆盖 18 个方向：

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

## 当前 Pilot 校准

2026-06-17 使用本地 llama.cpp + Qwen27B 跑通了 clean 9-case pilot：

- raw verifier log：5/9 pass；
- BPFix structured JSON：9/9 pass。

这轮结果说明 structured diagnostic 已经能帮助当前 pilot 中 4 个 raw-failing case：

- `alu32_pointer_cookie_001`：raw 保留 pointer-shift inline asm；
- `map_value_pointer_cookie_001`：raw 仍对 map-value pointer 做 bitwise arithmetic；
- `ringbuf_pointer_cookie_001`：raw 仍对 ringbuf pointer 做 bitwise arithmetic；
- `xdp_adjust_head_map_value_001`：raw verifier 可过但 post-adjust packet offset 错，
  功能 oracle 失败。

这个结果证明 runner 和 oracle 能端到端工作，但也证明当前 pilot 远未达到 hard
suite 难度目标：raw-log 成功率 55.6%，仍高于 30%。新增 map-value case 暴露并修复了
一个 oracle 过窄问题：旧检查只接受 map-value 状态和 load 出现在同一行 verifier 文本
里的布局；现在改成跟踪 annotated trace 寄存器状态。`xdp_adjust_head_map_value_001`
还暴露了 structured hint 只表达 verifier proof 不够的问题：修复需要说明 positive
`bpf_xdp_adjust_head()` 会移动 packet head，新 `ctx->data` 从剥掉的 header 后开始。
按照上面的失败解释，下一阶段必须继续增加组合型 hard cases，并改进 structured
diagnostic 对 proof-loss 修复约束的表达，直到 raw-log one-shot 低于 30%，才能把它
作为论文 benchmark 结果使用。

同日新增 4 个更难的组合 case 后，用同一模型/config 在 tightened oracle 上重跑：

- raw verifier log：0/4 pass；
- BPFix structured JSON：3/4 pass。

新增 case 主要覆盖两个 raw-log 弱点：一是 raw 模型会把 prohibited pointer shift
改成另一个 bitwise mask，仍然破坏 verifier pointer provenance；二是
`bpf_xdp_adjust_head()` 后即使 verifier load 通过，也容易按旧 L2 packet layout
解析，导致功能 oracle 失败。tightened oracle 还暴露了一个 structured-mode
残余失败：`ringbuf_branch_cookie_001` 的候选修复了 verifier reject，但只保留
一个 submitted ringbuf mark，丢掉了 UDP/TCP branch-derived mark 的区分。为支持这些
case，BPFix 诊断也做了两点工程修正：

- stale packet pointer signal 现在能从 verifier state 中识别“helper 前是 packet
  pointer、helper 后同一寄存器变 scalar、期间没有显式重写”的 proof loss；
- pointer-shift lowering help 明确指出不要把 verifier pointer 通过 `__u64/long`
  cookie 位移或 mask 后再 cast 回来，应该删除 cookie/shadow round trip 并使用原始
  checked pointer。

合并当时 13 个 pilot cases 后：

- raw verifier log：5/13 pass，38.5%；
- BPFix structured JSON：12/13 pass，92.3%。

当时仍然不能声称已达到 hard-suite 目标，因为 raw 38.5% 还高于 `<30%`。但新增 4 个
case 说明构造“raw 难、structured 多数可修”的组合场景是可行的，下一步至少还需要再
加入 4 个 raw-failing admitted cases 才可能把当前模型/config 下的 raw pass rate
压到 30% 以下。

随后继续校准时发现 3 个候选 case 被 raw Qwen27B 直接修好：

- `dynptr_slice_cookie_001`；
- `map_value_two_lookup_cookie_001`；
- `ringbuf_map_cookie_001`。

这些 case 不作为当前 hard-mode admitted corpus 计数。如果未来重新引入，它们只能
作为种子，并且必须增加额外、非同构的 proof obligation 后才能重新 admitted。为避免把容易样本或
按单一模型筛选出的样本包装成泛化结论，pilot 文档把这类剔除显式记录为 calibration
exclusions。

同日新增并 admitted 5 个组合 case 后，在该批次相同模型/config 下得到：

- raw verifier log：0/5 pass；
- BPFix structured JSON：5/5 pass。

把已记录的 9-case、4-case 和 5-case runs 做算术 roll-up 后：

- raw verifier log：5/18 pass，27.8%；
- BPFix structured JSON：17/18 pass，94.4%。

这个 roll-up 达到 pilot hard-suite raw `<30%` 难度门槛，但它不是一次同
max-token 配置下的完整 18-case suite run，也不是 paper-ready 结果。admitted 数量
只有 18，新增 5 个 case 仍高度集中在 pointer-cookie provenance 模式，且 case
admission 使用了本地 Qwen27B 校准。论文阶段仍必须扩到至少 100 个 case，加入其他
模型/trimmed raw baseline，重新用同一配置跑完整 suite，并由独立 reviewer 审核每个
case 的 bug、oracle、signal 多样性和是否过拟合某个 prompt/model。
