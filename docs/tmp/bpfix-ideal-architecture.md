# BPFix 理想设计架构

这份文档记录当前讨论出来的理想架构方向。它不是当前实现状态说明，而是后续重构和论文/开源叙事应该对齐的目标。

## 一句话定位

BPFix 是一个用户态 eBPF verifier 诊断工具：输入 verifier log，必要时结合 BPF object/BTF/CFG，把 verifier 拒绝原因解释成接近 Rust compiler diagnostic 的 required-proof 诊断。

## 核心原则

1. `bpfanalysis` 是底层分析基础设施，应该尽量保持和 `bpfopt` 一致的形态。
2. `bpfix` 是用户可见的诊断产品层，负责规则、taxonomy、说明文案、repair hint 和 CLI/JSON 输出。
3. 普通用户路径不依赖 `case.yaml`。YAML 只用于 benchmark/evaluation，对照判断正确率。
4. 主流程应该是 log analyzer，不是 command wrapper。`bpfix check -- <command>` 可以以后作为便利功能，但不应该是核心卖点。
5. CFG 不应该从 log 直接“解析出来”。CFG 来自 object/instruction stream；verifier log 解析成 per-PC verifier states；二者再通过 PC/InsnSite 关联。

## 分层职责

### bpfanalysis

`bpfanalysis` 应该提供低层、可复用、尽量中性的分析能力：

- BPF instruction 表示和解码
- BPF object / section / instruction stream 读取
- verifier log state parser
- `ProgramCFG` 构建
- verifier states 按 PC/InsnSite 绑定到 CFG
- use-def graph
- liveness
- register/value lineage primitives
- BTF func/line info 解析和 source mapping primitive

`bpfanalysis` 不应该包含 BPFix 产品语义：

- 不放 `BPFIX-E*` taxonomy
- 不放用户可见错误文案
- 不放 repair hint
- 不放 “source_bug / lowering_artifact” 产品分类规则
- 不放面向 README/demo 的 special case

换句话说，`bpfanalysis` 输出事实和结构，不输出产品诊断。

### bpfix

`bpfix` 是诊断工具层，负责把 `bpfanalysis` 的事实解释成用户能理解的诊断：

- CLI 输入处理
- verifier log region extraction
- `--object prog.o` 参数处理
- terminal verifier error 提取
- terminal error -> required proof 映射
- proof lifecycle 规则
- `BPFIX-E*` error code
- `source_bug / lowering_artifact / verifier_limit / environment_or_configuration` 分类
- repair hint 排序
- Rust-style text rendering
- JSON schema

这里可以有规则和启发式，但它们应该显式属于 BPFix 诊断层，而不是混进 `bpfanalysis`。

## 推荐的数据流

### 只有 verifier log 时

```text
verifier log
  -> bpfix: extract verifier log region
  -> bpfanalysis: parse verifier states keyed by PC
  -> bpfix: find terminal error
  -> bpfix: infer required proof
  -> bpfix: best-effort proof lifecycle from log states/source comments
  -> bpfix: render diagnostic
```

这个路径必须独立可用，因为真实用户最容易拿到的是 verifier log。

### 有 object 和 verifier log 时

```text
prog.o
  -> bpfanalysis: read BPF instructions / BTF / line info
  -> bpfanalysis: build ProgramCFG

verifier log
  -> bpfanalysis: parse verifier states keyed by PC

ProgramCFG + verifier states
  -> bpfanalysis: attach states to InsnSite
  -> bpfanalysis: expose use-def / liveness / value lineage facts

bpfix
  -> infer required proof from terminal error
  -> use CFG/use-def/liveness/state transitions to locate:
       proof established
       proof lost
       rejected
  -> map events to source spans using BTF/log comments
  -> render diagnostic
```

这个路径才是更硬的算法核心，也是后续论文和社区价值应该强调的方向。

## CFG 和 log 的关系

不应该设计成：

```text
verifier log -> CFG
```

应该设计成：

```text
object/instructions -> CFG
verifier log         -> states by PC
CFG + states         -> states attached to InsnSite
```

原因：

- CFG 是程序结构，应该来自真实 BPF instruction stream。
- verifier log 是 verifier 运行轨迹和 abstract state snapshots，不是完整程序表示。
- log 可能缺 instruction、缺路径、缺 BTF/source 信息。
- object 和 BTF 能补足 log-only 模式无法稳定恢复的信息。

## Required Proof 命名

内部/论文可以使用：

```text
ProofObligation
```

但用户输出里不建议直接叫 `obligation`，太学术。CLI 和 README 应该使用：

```text
required proof
```

例如：

```text
= required proof: r5 must still be a verifier-tracked packet pointer here
```

含义是：verifier 在这个程序点需要看到某个安全证明，但当前 bytecode/log 里这个证明缺失或丢失。

## YAML 的位置

`case.yaml` 不属于 runtime path。

它的职责是 evaluation oracle：

- 记录人工标注的 expected error id
- 记录 expected taxonomy class
- 记录 expected rejected/root-cause location
- 记录 expected repair direction
- 用来计算 BPFix 输出的正确率

普通用户运行：

```bash
bpfix verifier.log
bpfix --object prog.o verifier.log
```

不应该依赖 `case.yaml`。

## 最理想的社区使用方式

第一阶段主流程：

```bash
make load 2>&1 | tee verifier.log
bpfix verifier.log
```

或者：

```bash
sudo bpftool prog load xdp.o /sys/fs/bpf/xdp 2> verifier.log
bpfix --object xdp.o verifier.log
```

`bpfix check -- <command>` 暂时不是主流程。它可以以后作为 convenience wrapper，但会引入 stdout/stderr 顺序、TTY、sudo、交互、长日志 capture、exit code 等不稳定因素。

## 后续重构方向

1. 把已经放入 `bpfanalysis` 的 BPFix 产品规则迁回 `bpfix`。
2. `bpfanalysis` 保留 verifier state parser，但只输出结构化 facts。
3. `bpfix` 新增内部 diagnostic 模块，承载 taxonomy、required proof、proof lifecycle rules、repair hints。
4. 实现 `--object prog.o` 的真实 object/BTF 读取。
5. 用 object instruction stream 构建 `ProgramCFG`。
6. 把 verifier states attach 到 `InsnSite`。
7. 用 use-def/liveness/value lineage 追踪 copy、spill、reload、branch join。
8. 从 state transition 中定位 proof established / proof lost / rejected。
9. 用 BTF line info 生成 source spans；log comments 只作为 fallback。
10. 用 `case.yaml` corpus 做 accuracy evaluation，而不是运行时依赖。

## 最终目标

最终的 BPFix 不应该只是 prettier verifier logs，也不应该只是 regex rule collection。

目标应该是：

```text
verifier trace + object CFG + use-def/liveness + BTF
  -> source-level proof lifecycle diagnostic
```

这才是对社区有用、也有创新性的形态。
