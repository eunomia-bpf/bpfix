# BPFix：计划与进度

> **项目名称**：BPFix（原 BPFix）— Automated Diagnosis and Repair of eBPF Verifier Failures

> ## **第一优先级：实现必须配得上 claims，不是降 claims 配实现。目标 OSDI/ATC。**
>
> Critical review (2026-03-13) 发现论文 claims 与代码严重脱节。方向不是降低 claims，而是**重新实现核心引擎**使其配得上 OSDI/ATC level 的 novelty。具体见 §10 Implementation Gap Closure Plan。

> 本文档是 BPFix 项目的单一 hub。
> **编辑规则**：
> - 任何 TODO/实验/文档引用条目被取代时，必须至少保留一行并标注状态，不得直接删除。
> - 每个任务做完 → 立即更新本文档（任务条目状态 + 关键数据 + 文档路径）。
> - 每次 context 压缩后 → 完整读取本文档恢复全局状态。
> - 用 codex CLI 跑所有实现/分析任务。
> 上次更新：2026-03-20（eval set 大规模改进：独立标注、编译验证、stratified reporting、baseline 重建）

---

## 0. 当前快照（2026-03-20）

- **Ground truth**: `case_study/ground_truth.yaml` — 138 cases（136 non-quarantined），独立双 LLM 标注 + adjudication（κ=0.737，18/18 manual calibration match）
- **分布**: source_bug 100, lowering_artifact 19, environment_or_configuration 15, verifier_limit 4, quarantined 2
- **编译验证**: selftest 85/85 compiled+rejected; SO/GH 37/51 compiled, 30 rejected; cilium 43/50 compiled (0 loaded, libbpf legacy map issue); eval_commits bcc 1 confirmed cross-kernel on 5.10
- **Taxonomy (rebuilt baseline)**: BPFix 80.1% vs Regex Baseline 80.9%（all 136）; selftest BPFix 领先; external BPFix 54.9% vs Baseline 62.7%
- **Localization**: proof_lost coverage 8.8% (12/136); accuracy when present within-5 66.7%
- **Fix-type**: 72.8% overall
- **Baseline**: regex baseline 已吸收 PV 做法，PV 不再作为独立 baseline
- Tests：**406 passing**（2 skipped）
- Latency：median ~32ms, P95 ~42ms
- QEMU 5.10 环境可用（Debian 11 nocloud, `scripts/qemu-*.sh`）
- Eval 脚本统一用 `ground_truth.yaml`，stratified reporting（selftest vs real-world vs all）
- Cross-log 诊断稳定性：38/51 taxonomy match between original and fresh verifier logs

---

## 1. 论文核心要求

### 1.1 核心 Thesis（2026-03-18 第五次调整）

> **历史调整**：
> - v1：verifier 缺诊断信息 → 发现 LOG_LEVEL2 已有完整 abstract state
> - v2：分类准确率 ≠ 贡献（LLM 95%+）→ 贡献是 diagnostic quality
> - v3：proof obligation lifecycle → obligation inference 本质是 lookup table
> - v4：abstract state transition analysis → "不需要知道 obligation"（overclaim，已修正）
> - **v5（当前）**：cross-analysis classification + diagnosis-guided repair

> **当前 thesis**：
> eBPF verifier 的 LOG_LEVEL2 trace 是完整的 proof attempt 记录（per-instruction abstract state）。
> BPFix 从 BPF ISA specification（opcode byte）推断 rejection 处的 safety condition（register-parametric schema，不绑定具体 register），
> 然后通过 **(1) 在 proof-compatible carriers 上监控 proof lifecycle（establishment + loss）** 和 **(2) 从 rejection 点的 backward slice** 交叉比较，分类 failure mode：
>
> 前置过滤：structural classes（environment_or_configuration, verifier_limit, verifier_false_positive）由 error_id 直接分类，不进入 cross-analysis。
>
> Cross-analysis（仅对 proof-obligation failures）：
> - 存在 on-chain establishment **且** 存在 later on-chain loss → **established_then_lost**
> - 无 on-chain establishment，但存在 off-chain proof-compatible carrier establishment → **lowering_artifact**
> - 无任何 proof-compatible carrier establishment → **source_bug**
> - 证据不足（partial trace、多 obligation 冲突、loop-carried ambiguity） → **ambiguous**
>
> **关键改进（2026-03-18 design review 后）**：
> - Safety condition 是 **register-parametric schema**（如 `PacketBounds(size=1, ptr_kind=pkt)`），不是绑定具体 register 的公式
> - 监控范围是 **proof-compatible carriers**（同 pointer kind / provenance / alias class），不是"所有 register"
> - 分类需要 establishment **和** loss 两个 witness，不是只看 establishment
> - 增加 **ambiguous** bucket 处理 loop/merge/partial trace 等不确定情况
>
> 在此诊断基础上，BPFix 合成修复并通过 verifier oracle 验证。
>
> **Safety condition 推断是 ISA-driven**（opcode byte → required property），不是 error message pattern matching（Pretty Verifier 的 91 regex 做法）。这是工程稳定性选择，不是核心 novelty。
>
> 纯 userspace，不需要改 kernel。

**BPFix 输出示例**：
```
error[BPFIX-E005]: lowering_artifact — packet access with lost bounds proof
  ┌─ xdp_prog.c
   │
38 │     if (data + ext_len <= data_end) {
   │         ─────────────────────────── proof established
   │         R3: pkt(range=0) → pkt(range=14)
   │
42 │     __u16 ext_len = __bpf_htons(ext->len);
   │                     ────────────────────── proof lost: OR destroys bounds
   │                     R0: scalar(umax=255) → scalar(unbounded)
   │
45 │     void *next = data + ext_len;
   │                  ─────────────── rejected: pkt_ptr + unbounded
   │
   = note: Bounds check exists (line 38) but LLVM's lowering breaks it.
   = help: Add explicit clamp: if (ext_len > 1500) return XDP_DROP;
```

#### Verifier Log 已有的信息（LOG_LEVEL2）

```
; __u16 ext_len = __bpf_htons(ext->len);     ← BTF source line annotation
19: (71) r6 = *(u8 *)(r0 +2)                 ← instruction
20: R0=pkt(id=0,off=2,r=6)                   ← 完整 register abstract state
    R6_w=inv(id=0,umax_value=255,                (type, bounds, offset, range)
    var_off=(0x0; 0xff))
...
22: (4f) r0 |= r6                            ← critical transition
23: R0_w=inv(id=0)                            ← bounds 丢失！
...
math between pkt pointer and register with    ← final error (症状，不是原因)
unbounded min value is not allowed
```

**已有**：per-instruction register state (type/bounds/offset/range/var_off)、BTF source lines、backtracking annotations、control flow merge points

**缺失的（BPFix 要提取的）**：
1. Critical state transition — 在哪条指令 proof 丢失了（上例：insn 22 的 OR）
2. Causal chain — 从 error point 反向追溯到 root cause instruction
3. Source mapping — critical transition 对应源码哪一行
4. Error classification — stable error type（不是 free-text message）
5. Repair guidance — 应该怎么改

#### 类比定位

| 系统 | 输入 | 做了什么 | 没做什么 |
|------|------|----------|----------|
| Pretty Verifier (GitHub tool, 未发表) | error message 那一行 | regex 匹配 + source mapping | 不分析 state trace，跨版本 break |
| Model checking counterexample analysis | counterexample trace | 提取 property violation 原因 | 不适用于 eBPF abstract interpreter |
| **BPFix** | **完整 verifier state trace** | **state transition analysis + causal chain** | — |

#### 论文逻辑链条（2026-03-18 更新）

1. **Context + Problem (Para 1)**: eBPF critical → verifier rejection = 500-line trace → last line = symptom, root cause buried 30-500 lines earlier
2. **Evidence + Why existing fails (Para 2)**: 591 commits → 63.6% 是 proof-reshaping workarounds（根因是 verifier over-approximation）。修复需要知道 proof *在哪里*断了。PV regex on final line; LLMs treat as text; neither finds the state transition that broke the proof
3. **Key insight (Para 3)**: Verifier trace = proof attempt record。从 ISA spec 推断 safety condition，全局监控其 proof lifecycle，backward slice 找 causal chain，交叉比较判定 failure mode。Cross-analysis 能区分 source_bug、lowering_artifact、established_then_lost
4. **Example (Para 4)**: Figure 1 — bounds check established on R5 (line 3), but LLVM uses R3 for access → proof exists but not on causal chain → lowering_artifact。BPFix 诊断 + 合成修复 + verifier oracle 验证
5. **System + Results + Contributions (Para 5)**: Cross-analysis classification + end-to-end repair pipeline + evaluation

### 1.2 Novelty（2026-03-18 第五次调整，design review 后修正）

**诚实定位**：novelty 是 domain-specific composition over eBPF verifier traces，不是 new general analysis paradigm。Monitoring、slicing、generate-and-validate 都不新。新的是应用到 eBPF + 区分 lowering artifact + verifier-in-the-loop repair。

**论文三大贡献**：
1. **Proof-carrier-aware cross-analysis** — 在 proof-compatible carriers 上监控 establishment+loss，与 backward slice 交叉判定 failure mode。比单独的 monitor 或 slice 更精确，尤其能区分 lowering artifact（proof 在 off-chain carrier 上存在但编译器断开了连接）。是 domain-specific diagnostic heuristic，不是 generally sound classifier
2. **End-to-end diagnostic + repair pipeline** — 4 层架构：parse → analyze → present (Rust-style multi-span) → repair (diagnosis-guided generate-and-validate with verifier-in-the-loop)。纯 userspace，不改 kernel。注意：不是 CEGAR（不 refine abstraction），是 diagnosis-guided repair loop
3. **Evaluation on 302 real-world failures** — 数字待重跑确认。核心 benchmark 应缩小到 ~60-80 trace-rich manually labeled cases

**与 Pretty Verifier 的本质差异**：
- Pretty Verifier：parse **1 行** error message（91 regex）→ 1 个 enhanced text + 1 个建议
- BPFix：parse **500 行** state trace → cross-analysis + **多个源码位置** + 因果链 + 合成修复

**Novelty 不是**（诚实承认）：
- ISA-driven safety condition inference = 工程选择（opcode lookup table vs error message regex），不是核心 novelty
- "Second-order abstract interpretation" = overclaim，已删除
- 修复 loop 不是 CEGAR — 不 refine verifier abstraction，是 search-based patch generation

**Go 条件（全部满足才提交）**：
1. ≥80 labeled cases ✅ 302 cases, 30 manual
2. End-to-end pipeline 跑通 ✅ 262/262 batch success
3. Cross-analysis classification 实现 ❌ 待实现 (#78)
4. 至少 1 个 lowering artifact case 端到端自动修复验证 ❌ 待验证（codex 在跑）
5. Synthesis + verifier oracle loop 实现 ❌ 待实现 (#66-#68)
6. 重跑全部 eval ❌ 待做 (#58)

### 1.3 与 existing work 的关键差异

| Work | 做了什么 | 没做什么（我们的空位） |
|------|----------|----------------------|
| Deokar et al. (eBPF'24) | 743 SO 问题，19.3% verifier | 只描述痛点 |
| HotOS'23 | Verifier untenable 论证 | 没提出新工具 |
| Rex (ATC'25) | 72 workaround commits 分类 | 回顾性分析，不是工具 |
| Pretty Verifier (GitHub, 未发表) | 83 regex handlers + source mapping | **只 parse error message，不分析 state trace**；跨版本 break |
| Kgent (eBPF'24) | verifier text → LLM loop | raw text 限制质量 |
| SimpleBPF / verifier-safe DSL | DSL 绕开 verifier | 只覆盖 DSL 子集 |
| ebpf-verifier-errors | 社区收集 log+fix | 手动, 无分析工具 |

### 1.4 核心设计约束

1. **纯 userspace** — 不需要 kernel patch，解析现有 verbose log
2. **Agent 是 application，不是 contribution** — 论文贡献是 trace analysis，不是 agent
3. **分析 state trace，不只是 error message** — 这是与 Pretty Verifier 的核心区别
4. **Passes verifier ≠ semantic correctness** — 必须有 task-level oracle
5. **Register state format stability > error message stability** — 跨版本稳定性的基础

---

## 2. 设计架构

### 2.0 四层架构概览

```
Layer 1: PARSING（文本 → 结构化数据，regex 是合理的 lexer）
  输入: raw verifier LOG_LEVEL2 text (500+ 行)
  输出: TracedInstruction[] — (insn_idx, opcode_hex, pre_state, post_state, btf_source)
  实现: log_parser.py + trace_parser.py

Layer 2: ANALYSIS（纯结构化，零 regex）

  Step A: Safety condition inference + operand role identification
    从 error instruction 的 opcode byte 推断 register-parametric obligation schema
    如 PacketBounds(size=1, ptr_kind=pkt)，不绑定具体 register
    同时确定 slice seed registers 和 candidate proof carriers
    实现: opcode_safety.py + helper_signatures.py

  Step A': Structural class filtering
    error_id 直接分类 environment_or_configuration / verifier_limit / verifier_false_positive
    只有 proof-obligation failures 进入 Step B-D

  Step B: Proof-carrier-aware monitoring (与 C 并行)
    在 proof-compatible carriers 上监控 obligation schema
    carriers = 同 pointer kind / provenance / alias class 的 registers
    记录 per-carrier establishments + losses（不是只记一个）
    实现: monitor.py (需扩展为 per-carrier)

  Step C: Backward slice from error (与 B 并行)
    CFG reconstruction + reaching definitions + control dependence
    Slice = backward_slice(error_insn, error_register)
    实现: cfg_builder.py + dataflow.py + control_dep.py + slicer.py

  Step D: Cross-analysis classification
    需要 establishment + loss 两个 witness:
    - on-chain establish + later on-chain loss → established_then_lost
    - no on-chain establish, off-chain compatible carrier establish → lowering_artifact
    - no establish on any compatible carrier → source_bug
    - insufficient evidence (partial trace / loop / merge) → ambiguous
    实现: pipeline.py (待实现 #78)

  输出: Diagnosis(obligation_schema, classification,
                   per_carrier_lifecycle, backward_slice, gap)

Layer 3: PRESENTATION
  输入: Diagnosis + BTF source annotations
  输出: Rust-style multi-span diagnostic (3-5 labeled spans) + structured JSON
  实现: source_correlator.py + renderer.py

Layer 4: REPAIR（待实现 #66-#68）

  Phase 1: Local proof-preserving repairs
    clamp/mask insertion
    null-check insertion
    redundant bounds-check insertion
    __always_inline annotation
    expression reuse (replace dereference with checked pointer)

  Phase 2: Structural repairs (更复杂，覆盖 pilot case 类型)
    loop rewrite templates (bounded iteration + cursor)
    bounded-cursor conversion
    multi-location structural rewrites

  Verifier oracle: compile → bpftool prog load → pass/fail
  Iterative: diagnosis-guided generate-and-validate (不是 CEGAR)

  实现: synthesizer.py + verifier_oracle.py
```

---

## 3. 领域分析

### 3.1 五类 Failure Taxonomy

| Class | 含义 | 典型信号 | 占比 |
|-------|------|----------|:---:|
| `source_bug` | 源码真缺 bounds/null/refcount check | "invalid access to packet", "invalid mem access" | **88.1%** (266/302 heuristic) |
| `lowering_artifact` | LLVM 生成 verifier-unfriendly bytecode | "unbounded min value" after spill/reload | **4.0%** (12/302) |
| `verifier_limit` | 程序安全但超了分析能力 | "too many states", "loop not bounded" | **1.3%** (4/302) |
| `environment_or_configuration` | helper/kfunc/BTF/attach target 不匹配 | "unknown func", "helper not allowed" | **6.3%** (19/302) |
| `verifier_false_positive` | verifier 自己的 bug | regression across versions | **0.3%** (1/302) |

**人工验证**：30 cases labeled，heuristic agreement 76.7%（κ=0.652）。Lowering artifacts 系统性被误分类为 source_bug（4/6）。

**决策顺序**（消歧义时）：verifier_false_positive → environment_or_configuration → lowering_artifact → verifier_limit → source_bug

**完整定义**：`bpfix-bench/taxonomy.yaml`

### 3.2 Error Catalog

当前 23 个 stable error IDs（BPFIX-E001 ~ E023），覆盖率 87.1%（263/302）。

| ID | Short Name | Class | Matches | 典型 verifier message |
|----|-----------|-------|:---:|----------------------|
| E001 | packet_bounds_missing | source_bug | 18 | "invalid access to packet" |
| E002 | nullable_map_value_dereference | source_bug | 8 | "invalid mem access 'map_value_or_null'" |
| E003 | uninitialized_stack_read | source_bug | 9 | "invalid indirect read from stack" |
| E004 | reference_lifetime_violation | source_bug | 17 | "Unreleased reference id=" |
| E005 | scalar_range_too_wide_after_lowering | lowering_artifact | 23 | "unbounded min value" |
| E006 | provenance_lost_across_spill | lowering_artifact | 0 | "expected pointer type, got scalar" |
| E007 | verifier_state_explosion | verifier_limit | 1 | "too many states" |
| E008 | bounded_loop_not_proved | verifier_limit | 1 | "loop is not bounded" |
| E009 | helper_or_kfunc_unavailable | environment_or_configuration | 3 | "unknown func" |
| E010 | verifier_false_positive_or_regression | verifier_false_positive | 1 | "kernel BUG at" |
| E011 | scalar_pointer_dereference | source_bug | 38 | "invalid mem access 'scalar'" |
| E012 | dynptr_protocol_violation | source_bug | 22 | "Expected an initialized dynptr" |
| E013 | execution_context_discipline | source_bug | 19 | "cannot restore irq state" |
| E014 | iterator_state_protocol | source_bug | 10 | "expected an initialized iter_num" |
| E015 | trusted_arg_nullability | source_bug | 8 | "Possibly NULL pointer passed" |
| E016 | helper_kfunc_context_restriction | environment_or_configuration | 12 | "cannot be called from callback" |
| E017 | map_value_bounds_violation | source_bug | 1 | "invalid access to map value" |
| E018 | verifier_analysis_budget_limit | verifier_limit | 2 | "combined stack size" |
| E019-E023 | (round 2 expansion) | mixed | 59 | various |

**完整定义**：`interface/catalogs/error_catalog.yaml`

### 3.3 Verifier state trace 包含什么

每条指令的 register state dump：
```
R0=pkt(id=0,off=2,r=6,imm=0)    → type=pkt, offset=2, range=6
R1=inv(id=0,umax=255,var_off=(0x0;0xff))  → type=scalar, bounds=[0,255]
fp-8=map_value(off=0,ks=4,vs=8)  → stack slot, map value pointer
```

Control flow annotations：
```
from 67 to 109: R0=inv0 R1_w=inv0 ...   → branch merge
last_idx 39 first_idx 36                  → backtracking
regs=1 stack=0 before 38: (c7) r0 s>>= 32  → which earlier insn affected current state
```

BTF source lines：
```
; if (data_end < (data + ext_len)) {      → source annotation
42: (bf) r3 = r1
```

### 3.4 BPFix 输出格式示例

**Pipeline**：raw verifier log → 5 步 → Rust-style multi-span output

#### Step 1: Enhanced Backtracking Extraction
利用 verifier 自己的 `mark_precise` backtracking（已在 LOG_LEVEL2 中输出）：
```
last_idx 24 first_idx 12           ← 反向追踪范围
regs=1 stack=0 before 23: (dc) r0 = be16 r0    ← R0 (bit 0)
regs=41 stack=0 before 21: (67) r0 <<= 8       ← R0+R6 (bits 0,6)
```
提取为结构化 `BacktrackChain`，替代我们的启发式 causal chain。

#### Step 2: Proof Obligation Inference + Propagation
**义务推断**：从 error message + register state 推导 verifier 的 proof requirement：
- Packet: `reg.type==pkt && reg.off+size <= reg.range`
- Map value: `0 <= reg.off && reg.off+size <= value_size`
- Stack: `reg.off` within frame bounds
- Helper arg: `reg.type == expected_type`
- Null check: `reg.type != *_or_null`

**证明传播分析**：从 proof-establishing branch 正向追踪：
- 找到 narrowing branch（`if r5 > r2 goto` → R0.range 变窄）
- 追踪 proof 是否通过 copy/move 传播到实际被访问的 register
- 没有传播 → lowering artifact（compiler 用了不同 register）
- 没有建立 → source bug

#### Step 3: Source Correlation via BTF
- 从 trace 的 `; source_text @ file:line` 提取 BTF source mapping
- 每个 proof event（建立/传播/丢失/拒绝）映射到源码位置
- 连续 bytecode 指令合并为单个 source-level span

#### Step 4: Multi-Span Diagnostic Renderer
**Human-readable（Rust-style）**：多个源码位置 + 角色标签 + register state 变化 + note/help
**Structured JSON**（供 LLM/CI 消费）：
```json
{
  "error_id": "BPFIX-E005",
  "taxonomy_class": "lowering_artifact",
  "proof_status": "established_then_lost",
  "spans": [
    {"role": "proof_established", "source": {"file": "xdp_prog.c", "line": 38},
     "insn_idx": 8, "source_text": "if (data + ext_len <= data_end)",
     "state_change": "R3: pkt(range=0) → pkt(range=14)"},
    {"role": "proof_lost", "source": {"file": "xdp_prog.c", "line": 42},
     "insn_idx": 22, "source_text": "__bpf_htons(ext->len)",
     "state_change": "R0: scalar(umax=255) → scalar(unbounded)",
     "reason": "OR operation merges byte values, destroying bounds"},
    {"role": "rejected", "source": {"file": "xdp_prog.c", "line": 45},
     "insn_idx": 24, "source_text": "void *next = data + ext_len",
     "state_change": "R5: pkt_ptr + unbounded scalar"}
  ],
  "obligation": {"type": "packet_access", "required": "reg.off+size <= reg.range"},
  "note": "Source has valid bounds check but LLVM lowering breaks it",
  "help": "Add explicit clamp: if (ext_len > 1500) return XDP_DROP;"
}
```

### 3.5 技术挑战

1. **Meta-analysis of abstract interpretation** — 对 verifier 输出的 per-instruction abstract state 做二阶分析（backward slicing + proof propagation）
2. **Leveraging `mark_precise`** — verifier 自己的 precision tracking 是最精确的根因链，但只以 debug text 暴露
3. **Proof obligation inference** — 从 error message pattern 推导形式化的 proof requirement，不是 pattern matching
4. **Source correlation** — BTF annotation 并非总是存在；需要 fallback 到 bytecode-level spans
5. **Information compression** — 500 行 → 3-5 个 spans，选择标准：proof lifecycle 的关键节点

### 3.6 Case Corpus 摘要

| 来源 | Cases | 特点 | 文档 |
|------|:---:|------|------|
| Kernel selftests | 200 (可扩展到 1026) | `__msg()` 标注 expected error；66 memory/bounds, 53 dynptr/iterator, 34 control-flow/locking, 25 ref lifetime, 12 nullability | `docs/tmp/selftests-collection-report.md` |
| Stack Overflow | 76 | 66 有 verifier log, 59 有源码, 66 有 fix description | `docs/tmp/stackoverflow-collection-report.md` |
| GitHub issues | 26 | Cilium 7, Aya 18, Katran 1；含 verifier regression case | `docs/tmp/github-collection-report.md` |
| **Total** | **302** | 目标 ≥80 labeled，实际远超 | — |

**注意**：302 cases 中有完整 verbose log（含 state trace）的主要是 SO 和 GitHub 来源。Kernel selftests 只有 expected error message，没有完整 state dump。后续需要补充 selftests 的完整 verbose log。

### 3.7 Synthetic Cases from eval_commits

从 591 个 eval_commits 中提取 C 代码，生成 535 个 synthetic case（`case_study/cases/eval_commits_synthetic/`）。每个保留完整 provenance（original_case_id, original_commit, original_repository, original_commit_message）。

| Taxonomy | Count |
|----------|:---:|
| lowering_artifact | 249 |
| source_bug | 220 |
| verifier_limit | 50 |
| environment_or_configuration | 16 |

**Total eval corpus**: 241 有 log + 535 synthetic = **776 cases**。`docs/tmp/synthetic-cases-report.md`

---

## 4. 决策记录

| 决策 | 原因 | 日期 |
|------|------|------|
| 题目不写 "LLM + eBPF" | Reviewer 会当 prompt engineering | |
| Agent 是 application 不是 contribution | 论文核心是 diagnostic quality | |
| 纯 userspace，不改 kernel | Verifier LOG_LEVEL2 已输出完整 abstract state | |
| Passes verifier ≠ 成功 | 必须有 semantic oracle | |
| 分类准确率不是贡献 | LLM 已做到 95%+。贡献是诊断质量 + 修复引导 | |
| Rust-style multi-span 是目标输出 | 类比 Rust borrow checker。没人对 eBPF 做过 | |
| 放弃 "obligation extraction" framing | 本质是 lookup table | |
| Pretty Verifier 未发表 | 只是 GitHub 项目，不构成 peer-reviewed prior art | |
| Language-agnostic | bytecode level 分析 → C/Rust/Go 都适用 | |
| 63.6% framing 需修正 | 根因是 verifier over-approximation，不是 diagnostics 差 | |
| 单 agent 做 build+code+test | 拆分 → test agent 发现 bug 但无法修复 | |
| 实现必须配得上 claims | 不是降 claims 配实现，是做到 claims 水平 | 2026-03-13 |
| **目标 OSDI/ATC** | 不降级到 workshop/tools track | 2026-03-13 |
| 读 verifier abstract state 是正确做法 | verifier output = ground truth，重算 transfer function 无意义 | 2026-03-18 |
| 不重算 verifier 的 interval arithmetic / transfer function (A2/A4/A5 不做) | verifier 已算好 abstract state，重算 = 重写 verifier.c 30K 行且更差 | 2026-03-18 |
| **Path B (synthesis + oracle loop) 是主要 novelty** | 诊断 = known techniques on new domain（够 ATC）。Synthesis 才够 OSDI | 2026-03-18 |
| **先 slice 再 monitor** | 先 backward slice 找相关指令，再在 slice 内评估 predicate | 2026-03-18 |

### Missing Citations（必须引用）
- Runtime verification: Bauer, Leucker, Schallhart (STTT 2011) — three-valued trace monitoring
- Model checking fault localization: SNIPER (Griesmayer 2006), BugAssist (Jose & Majumdar 2011)
- Error explanation: Groce & Visser (FSE 2003), Beer et al. (FMCAD 2009)
- Type error messages: Marceau, Morrisett, Findler (OOPSLA 2011)
- Program slicing: Weiser (1981) — 已引用但需更明确

与 BPFix 的区分：vs CEGAR（不 refine abstraction）、vs SFL（单 trace 不需多 trace）、vs SNIPER/BugAssist（CFG slicing 不是 MAX-SAT）

---

## 5. Eval Set 架构与使用

### 5.1 Corpus 架构

| 来源 | Case files | 有 trace-rich log | Eligible (≥50 chars) | 有 source_snippets |
|------|:---:|:---:|:---:|:---:|
| `kernel_selftests/` | 200 | 169 | 171 | 200 |
| `stackoverflow/` | 76 | 39 | 65 | 59 |
| `github_issues/` | 26 | 11 | 26 | 15 |
| **Logged total** | **302** | **219** | **262** | **274** |
| `eval_commits/` | 591 | 0 | — | 0 |
| `eval_commits_synthetic/` | 535 | 0 | — | 535 |

- **Primary eval corpus**: 262 eligible logged cases（`batch_diagnostic_eval.py` 的 `MIN_LOG_CHARS=50`）
- **Code-pair corpus**: 591 eval_commits（有 buggy/fixed code，无 verifier log；用于 repair experiment case selection）
- Case schema 按来源不同：selftests 有 `source_snippets` + `expected_verifier_messages`；SO 有 `question_body_text` + `selected_answer`；GH 有 `issue_body_text` + `fix`
- 无统一强制 schema。`case_study/schema.yaml` 是 aspirational，`eval_schema.yaml` 更接近但也不匹配

### 5.2 Ground Truth 架构

| 来源 | 数量 | 字段 | 存储位置 |
|------|:---:|------|----------|
| Manual 30-case labels | 30 | taxonomy, error_id, confidence, localizability, specificity, rationale, fix text | `docs/tmp/manual-labeling-30cases.md`（markdown 表格，多个 eval 脚本直接 parse） |
| Auto taxonomy labels | 262 | case_id, source, taxonomy, confidence, notes | `case_study/ground_truth_labels.yaml`（292 条，含 manual 30） |

- Ground truth **只有 taxonomy**，无 error_id、root_cause_line、fix_type、fix_code、instruction index
- 30 manual cases 是唯一可信的强标注；其余 262 是 heuristic/auto（msg_pattern 174, keyword 56, log_msg 17）
- 7 个 eligible cases 缺 ground truth label（如 `stackoverflow-68815540`, `github-aya-rs-aya-546`）

### 5.3 Eval Baselines

- **B1**: `raw_verbose_log` — 原始 verifier LOG_LEVEL2 verbose output（500-1000+ 行）
- **B2**: `regex_baseline` — 综合 error message regex（吸收了 PV 做法），1 行 error + taxonomy + suggestion
- **B3**: `bpfix_diagnostic` — BPFix Rust-style multi-span output

### 5.4 Eval 脚本使用方式

| 命令 | 脚本 | 功能 | 输出 |
|------|------|------|------|
| `make eval-batch` | `eval/batch_diagnostic_eval.py` | 262 cases 批量诊断 | `eval/results/batch_diagnostic_results.json` |
| `make eval-latency` | `eval/latency_benchmark.py` | 延迟 benchmark | `eval/results/latency_benchmark*.json` |
| `make test` | `pytest tests/` | 372 tests (5 skipped) | stdout |
| 直接运行 | `eval/span_coverage_eval.py` | span 覆盖 fix location | `eval/results/span_coverage_results.json` |
| 直接运行 | `eval/root_cause_validation.py` | proof_lost vs diff | `eval/results/root_cause_validation.json` |
| 直接运行 | `eval/taxonomy_coverage.py` | catalog 覆盖率 | `eval/results/taxonomy_coverage.json` |
| 直接运行 | `eval/pretty_verifier_comparison.py` | raw PV vs BPFix | `eval/results/pretty_verifier_comparison.json` |
| `make eval-repair-20b` | `eval/repair_experiment_v3.py` | A/B repair (本地 20B) | `eval/results/repair_experiment_results_v3.json` |

**Batch eval 流程**: case YAML → extract verifier_log → `generate_diagnostic()` → record results JSON。注意：batch eval **不比较** ground truth，只生成诊断结果；ground truth 对比在下游脚本中。

### 5.5 A/B Repair 实验设计

| 维度 | Condition A | Condition B |
|------|-------------|-------------|
| 输入 | buggy code + raw verifier log | buggy code + raw log + BPFix diagnostic |
| LLM 任务 | 生成修复代码 | 生成修复代码 |
| 测量 | verifier pass rate, fix-type accuracy, root-cause targeting | 同左 |
| 关键预测 | lowering_artifact: A 在 symptom site patch（错） | B 在 root cause site 修复（对） |

详细审计报告：`docs/tmp/eval-infrastructure-audit-2026-03-18.md`

---

## 6. 任务追踪

> **规则**：
> - 所有重要数据和文档路径只在本列表维护，不在别处重复。
> - 条目被取代时保留一行标注状态，不得删除。
> - 本表只能 append 新条目，不能开新 section。已有条目只能更新状态列和关键数据列，不能删除信息，只能压缩。

| # | 任务 | 状态 | 关键数据 / 文档 |
|---|------|:---:|------|
| 1 | Repo scaffold + CLAUDE.md | ✅ | `CLAUDE.md` |
| 2 | 文献综述 | ✅ | `docs/tmp/literature-survey.md` |
| 3 | Taxonomy 定义（5 classes） | ✅ | `bpfix-bench/taxonomy.yaml` |
| 4 | Error catalog（23 IDs, 两轮扩展） | ✅ | BPFIX-E001~E023, 87.1% coverage. `interface/catalogs/error_catalog.yaml`, `docs/tmp/catalog-expansion-round2-report.md` |
| 5 | Obligation catalog | ✅ | BPFIX-O001~O023. `interface/catalogs/obligation_catalog.yaml` |
| 6 | 诊断 JSON schema | ✅ | `interface/schema/diagnostic.json` |
| 7 | Log parser | ✅ | catalog-backed error line selection. `interface/extractor/log_parser.py` |
| 8 | Case collectors（3 scripts） | ✅ | `case_study/collect_{stackoverflow,kernel_selftests,github_issues}.py` |
| 9 | Kernel selftests collection | ✅ | **200 cases**. `docs/tmp/selftests-collection-report.md` |
| 10 | Stack Overflow collection | ✅ | **76 cases**. `docs/tmp/stackoverflow-collection-report.md` |
| 11 | GitHub issues collection | ✅ | **26 cases**. `docs/tmp/github-collection-report.md` |
| 12 | Taxonomy 覆盖分析 | ✅ | 87.1%（263/302）. `docs/tmp/taxonomy-coverage-report.md` |
| 13 | 人工标注 30 cases | ✅ | κ=0.652. `docs/tmp/manual-labeling-30cases.md` |
| 14 | Rex commits 收集 | ❌ 暂缓 | 优先做 engine |
| 15 | Verifier source analysis | ✅ | 90 check_\* 函数. `docs/tmp/verifier-source-analysis.md` |
| 16 | State trace parser | ✅ | `interface/extractor/trace_parser.py`, backtrack extraction. 9/9 tests |
| 17 | Diagnoser v1 | ✅ 已被新引擎取代 | 23/30 (77%). `docs/tmp/diagnoser-30case-evaluation.md`, `docs/tmp/diagnoser-report.md` |
| 18 | BTF source correlation | ✅ | `interface/extractor/source_correlator.py` |
| 19 | Multi-span renderer (Rust-style) | ✅ | `interface/extractor/renderer.py` |
| 20 | Pipeline entry point | ✅ | `interface/extractor/pipeline.py`, `generate_diagnostic()` |
| 21 | 旧 proof engine (heuristic) | ✅→已删除 | commit `32b75a6` 删除旧引擎 |
| 22 | Obligation catalog formal | ✅ | 35 FormalObligation from verifier.c. `obligation_catalog_formal.py` |
| 23 | Abstract domain (interval arithmetic) | ✅ | `abstract_domain.py`, tnum, 三值评估 |
| 24 | Value lineage | ✅ 不在主路径 | `value_lineage.py`, 20 tests |
| 25 | Multi-language analysis | ✅ | 25/25 non-C cases. `docs/tmp/multi-language-analysis.md` |
| 26 | Per-language eval | ✅ | C 274 / Rust 21 / Go 7. `eval/results/per_language_eval.json` |
| 27 | Decompiler analysis | ✅ | 不作为核心功能. `docs/tmp/decompiler-analysis.md` |
| 28 | 本地 LLM eval 基础设施 | ✅ | `scripts/local_llm_eval.py`, `docs/local-llm-guide.md` |
| 29 | Verifier oracle | ✅ | compile + bpftool prog load. `eval/verifier_oracle.py` |
| 30 | **Opcode-driven safety analysis** | ✅ | 7-case ISA decoder, zero keywords. `engine/opcode_safety.py`. commit `8fa1492` |
| 31 | **Helper signature table (UAPI)** | ✅ | 20+ helpers, ARG_CONTRACT conditions. `engine/helper_signatures.py`. commit `ed8c4e3` |
| 32 | **Gap-based establishment detection** | ✅ | gap >0→0 = establish, 0→>0 = loss. `engine/monitor.py`. commit `ed8c4e3` |
| 33 | **CFG reconstruction from trace** | ✅ | branch opcodes + `from X to Y`. `engine/cfg_builder.py`. commit `b24d29c` |
| 34 | **Reaching definitions analysis** | ✅ | forward pass, opcode-driven DEF/USE. `engine/dataflow.py`. commit `d58175f` |
| 35 | **Control dependence (post-dominator + CDG)** | ✅ | iterative fixed-point. `engine/control_dep.py`. commit `04f033c` |
| 36 | **Backward slice (data + control dep)** | ✅ | Weiser 1981 on trace CFG. `engine/slicer.py`. commit `dd975e4` |
| 37 | **Pipeline: remove heuristics from critical path** | ✅ | taxonomy/proof_status from engine only. commit `77848f9`. `docs/tmp/heuristic-removal-2026-03-18.md` |
| 38 | **Transition analyzer** | ✅ | per-instruction NARROWING/WIDENING/DESTROYING. `engine/transition_analyzer.py` |
| 39 | PV comparison (30 cases) | ✅ | BPFix 25/30 vs PV 19/30; root-cause 12/30 vs 0/30. `docs/tmp/pretty-verifier-comparison.md` |
| 40 | LLM classification experiment | ✅ | 所有条件 95%+, confirms classification ≠ contribution. `docs/tmp/llm-multi-model-experiment.md` |
| 41 | Cross-log stability | ✅ | 20/33 stable, 12/33 id-stable. `docs/tmp/cross-log-stability-analysis.md` |
| 42 | Batch diagnostic eval (v3, 241 cases; 已被新引擎取代) | ✅ 需重跑 | 241/241 成功. `docs/tmp/batch-diagnostic-eval-v3.md`, `docs/tmp/batch-diagnostic-eval.md` (v1, historical) |
| 43 | Span coverage eval | ✅ 需重跑 | 101/263 (38%), manual 12/14 (86%). `docs/tmp/span-coverage-eval.md`, `eval/span_coverage_eval.py`, `eval/results/span_coverage_results.json` |
| 44 | A/B repair v2 (54 cases, GPT-4.1-mini) | ✅ 需重跑 | lowering +30pp (3/10→6/10). `docs/tmp/repair-experiment-v2-results.md`, `docs/tmp/repair-experiment-report.md` (v1), `eval/repair_experiment.py`, `eval/results/repair_experiment_results.v2.json` |
| 45 | A/B repair v3 (56 cases, 本地 20B) | ✅ | B > A +7.1pp overall. `docs/tmp/repair-experiment-v3-results.md`, `eval/results/repair_experiment_results_v3.json` |
| 46 | Latency benchmark | ✅ 需重跑 | median 25.3ms, P95 41.2ms. `eval/results/latency_benchmark_v3.json` |
| 47 | Quality fix round 2 | ✅ | unknown taxonomy 14→2. `docs/tmp/quality-fix-round2-report.md` |
| 48 | Synthetic case generation | ✅ | 535 cases. `docs/tmp/synthetic-cases-report.md` |
| 49 | Synthetic compilation pilot | ✅ 失败 | 0/20 成功. `docs/tmp/synthetic-compilation-report.md` |
| 50 | Paper draft | ✅ 需重写 | `docs/paper/main.tex`, `docs/paper/main.pdf`, `docs/paper-outline.md` (historical). ACM SIGPLAN, 9 pages. **Claims 与代码严重脱节** |
| 51 | Paper numbers audit | ✅ | 6 discrepancies found. `docs/tmp/paper-numbers-audit.md`, `docs/tmp/paper-data-audit.md` |
| 52 | Paper claims analysis | ✅ | 70 claims, many overclaimed. `docs/tmp/paper-claims-analysis-2026-03-18.md` |
| 53 | Project review | ✅ | `docs/tmp/project-review-2026-03-18.md` |
| 54 | Cross-kernel stability eval | ❌ 暂缓 | QEMU/KVM, ≥3 kernel versions. `docs/tmp/cross-kernel-feasibility-report.md` |
| 55 | PV comparison on full corpus | ✅→已合并 | PV 做法已吸收进 regex baseline，不再单独比较 |
| 56 | Motivating example figure | ❌ | stackoverflow-70750259 |
| 57 | Pipeline figures | ❌ | pipeline 图 + Rust-style 输出示例 |
| 58 | **重跑全部 eval（新引擎）** | ❌ | 冻结引擎 → batch + span + latency + PV comparison |
| 59 | **扩展人工标注到 50-100 cases** | ❌ | 当前仅 30, lowering 仅 6 |
| 60 | **Path B: Repair synthesis** | ❌ | template catalog + instantiation + verifier oracle loop |
| 61 | **Path B: Batch synthesis eval** | ❌ | synthesis success rate on established_then_lost cases |
| 62 | **论文重写** | ❌ | 等引擎稳定 + eval 重跑后 |

| 63 | Novelty analysis | ✅ | 旧引擎 = 读预计算值 + field comparison，novelty 不够。`docs/tmp/novelty-deep-analysis-2026-03-13.md` |
| 64 | Missing citations audit | ✅ | 需引用 Bauer 2011, BugAssist (PLDI 2011), Weiser 1981, Groce & Visser (FSE 2003) |
| 65 | **重构 pipeline：先 slice 再 monitor** | ❌ | 当前 monitor 扫描全部指令，应先 backward slice 再在 slice 内 monitor |
| 66 | **Path B: Repair template catalog** | ❌ | bounds_collapse → `& MASK`; null → `if (!ptr) return`; range_loss → redundant bounds check |
| 67 | **Path B: Template instantiation** | ❌ | gap + condition + BTF source → 生成修复代码 |
| 68 | **Path B: Verifier oracle loop** | ❌ | synthesize → compile → bpftool prog load → pass/fail → 迭代 |
| 69 | **Path B: Batch synthesis eval** | ❌ | established_then_lost cases 合成成功率 |
| 70 | Deep output quality analysis | ✅ | 119 单 span 正确; false satisfied 3→0. `docs/tmp/output-quality-analysis.md` |
| 71 | Full code review | ✅ | 7 阶段 pipeline; 109/241 catalog override. `docs/tmp/full-code-review.md` |
| 72 | Strategic review | ✅ | `docs/tmp/strategic-review-2026-03-12.md` |
| 73 | Eval infrastructure audit | ✅ | `docs/tmp/eval-infrastructure-audit-2026-03-18.md` |
| 74 | **修 broken Makefile targets** | ✅ | v4/v5→current。`make eval-all` 通过。commit `135e50a` |
| 75 | **统一 corpus manifest** | ✅ | `case_study/eval_manifest.yaml` 统一定义 eligible cases。commit `d41e162` |
| 76 | **合并 ground truth 到一个文件** | ✅ | `case_study/ground_truth.yaml` — 138 cases，含 taxonomy + localization + fix_type + quality metadata。旧文件在 `case_study/archive/`。commit `02deced` |
| 77 | **补 7 个缺 label 的 eligible cases** | ✅→已被 v3 标注覆盖 | 独立双 LLM 标注覆盖了 139→138 core cases |
| 78 | **Cross-analysis classification（proof-carrier-aware）** | ❌ | register-parametric schema + proof-compatible carriers + establish+loss witness + ambiguous bucket。Design review 发现原始 E∩S 规则有 5 个反例 |
| 79 | **更新 §1/§2** | ✅ | thesis v5 + 4-layer v2 已更新（2026-03-18 design review 后） |
| 80 | Design review | ✅ | cross-analysis 不 sound as stated，需 proof-carrier + loss witness + ambiguous。`docs/tmp/design-review-2026-03-18.md` |
| 81 | Eval readiness review | ✅ | NOT READY for ATC/EuroSys。30 manual labels 不够，0 line-level annotation。`docs/tmp/eval-readiness-review-2026-03-18.md` |
| 82 | Repair pilot (stackoverflow-70760516) | ✅ | buggy rejected, fixed passes on local kernel. `docs/tmp/repair-pilot-case-2026-03-18.md` |
| 83 | **SafetyCondition → register-parametric schema** | ❌ | 当前 SafetyCondition 绑定具体 register，需改为 PacketBounds(size, ptr_kind) 等 schema |
| 84 | **Monitor → per-carrier lifecycle** | ❌ | 当前 TraceMonitor 只记一个 establish/loss，需改为 per-carrier map |
| 85 | **Corpus 分层：core_trace_rich / partial / message_only** | ✅ | eval_manifest.yaml 分层；报告 selftest vs external 分开。commit `37bb7e3` |
| 86 | **Selftest 去重** | ✅ | 85 core representative from 171 eligible。eval_manifest.yaml |
| 87 | **独立标注 138 trace-rich cases** | ✅ | 双 LLM 标注 + adjudication，κ=0.737，18/18 manual match。`ground_truth.yaml`。commit `84747e3` |
| 88 | **加 regex baseline + ablations** | ✅ | `core/baseline/regex_diagnostic.py` + 3 ablations。`eval/comparison_report.py`。commit `2d74c6f` |
| 89 | **Layer 4 Phase 1 local repairs** | ❌ | clamp/mask, null-check, redundant bounds, __always_inline, expression reuse |
| 90 | **Layer 4 Phase 2 structural repairs** | ❌ | loop rewrite, bounded-cursor, multi-location edits（pilot case 类型） |
| 91 | **Selftest 编译验证** | ✅ | 85/85 compiled + rejected。`case_study/cases/kernel_selftests_verified/`。commit `c5f4881` |
| 92 | **SO/GH 编译验证** | 进行中 | 37/51 compiled, 28 rejected, 4 confirmed。改进 wrapper 质量中 |
| 93 | **eval_commits lowering_artifact 扫描** | 进行中 | 312 candidates, 1 confirmed on 5.10 (eval-bcc-89c7f409b4a6)。批量 5.10 验证中 |
| 94 | **QEMU 5.10 cross-kernel 环境** | ✅ | Debian 11 nocloud, bpftool installed, scripts/qemu-*.sh。commit `50fafdc` |
| 95 | **Localization eval** | ✅ | `eval/localization_eval.py`。proof_lost coverage 8.8%, accuracy when present 66.7% within-5。commit `587bc66` |
| 96 | **Fix-type eval** | ✅ | `eval/fix_type_eval.py`。72.8% overall。commit `1ec1fca` |
| 97 | **Stratified reporting** | ✅ | selftest vs external vs all in comparison_report.py。commit `37bb7e3` |
| 98 | **死代码清理** | ✅ | 删 build_ground_truth_labels.py, 迁移 manual-labeling 依赖到 ground_truth.yaml。commit `587bc66` |
| 99 | **PV 做法合并进 regex baseline** | ✅ | regex baseline 已吸收 PV 的 error pattern 覆盖。PV 不再作为独立 baseline |
| 100 | **fix_type eval 去除 taxonomy leakage** | ❌ | 当前用 predicted_taxonomy 推断 fix_type，需要改为纯文本推断 |
| 101 | **end-to-end reproducibility 文档** | ❌ | 需要 README/artifact 说明 clone → eval → numbers |

