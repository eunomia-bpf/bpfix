# BPFix 开源可用性与 UX Hardening 建议

状态：建议稿，本轮已开始落实
日期：2026-06-13

## 结论

应该先把 BPFix 做成一个真正可用的开源 CLI，而不是继续优先扩 paper story。

当前代码已经有好的产品入口：`bpfix [LOG]`、stdin、plain text 默认输出、JSON
给 CI/editor/agent、benchmark replay 可以做回归。但核心诊断实现仍然明显是
partial：大量逻辑依赖 terminal string marker、source comment pattern 和有限的
verifier state parser。论文里也已经承认：很多 proof family 是
`classifier implemented, localization partial`，不是完整 root-cause proof。

所以开源化前最重要的不是再加复杂功能，而是：

1. 收窄承诺；
2. 去掉误导性 fallback；
3. 不再把 regex/heuristic 包装成完整证明分析；
4. 降低代码和依赖复杂度；
5. 让用户每次运行都能得到明确、有边界、不会乱建议的输出。

## 当前真实状态

我检查了 `README.md`、`docs/open-source-tool-design.md`、`docs/paper/main.tex`、
`crates/bpfix/src/main.rs`、`crates/bpfix/src/diagnostic.rs`、
`crates/bpfanalysis/src/object_file.rs` 和 CLI tests。

可保留的强项：

- CLI 入口已经合理：`bpfix [OPTIONS] [LOG]`，无参数读 stdin。
- 默认 plain text，`--format json` 给工具消费，这个 UX 是对的。
- noisy build/libbpf log region extraction 已有测试。
- YAML label 不会污染 runtime diagnostic，已有测试保护。
- `--object` 失败是 non-fatal，不会阻断基本 log diagnostic。
- examples 已覆盖 bpftool、libbpf C、libbpf-rs、Aya、BCC、CI、editor。
- evaluation 脚本能跑，当前 235-case replay log 都能输出 JSON。

本轮修改前的主要问题：

- 诊断分类仍由 `main.rs::classify()` 的 substring marker 决定。
- proof obligation 又在 `diagnostic.rs::infer_obligation()` 里重复实现一套 marker。
- source lifecycle span 很多来自 `looks_like_*` 函数，对源码注释做 pattern 猜测。
- fallback 输出 `BPFIX-UNKNOWN`，并默认 `failure_class = source_bug`，这对用户不安全。
- fallback help 仍会建议“move check closer / preserve exact register”，可能给错方向。
- `--object` 目前主要输出 CFG metadata，还没有真正提供 BTF-backed source correlation。
- README 对 object/CFG/source correlation 的描述容易让用户以为它已经能显著改善定位。
- 公共 CLI 仍直接支持 benchmark YAML，增加了产品路径复杂度。
- 默认 binary 依赖 `bpfanalysis`，而 `bpfanalysis` 又包含 object/CFG/pass/libbpf-sys 相关代码；
  对一个 log-first CLI 来说，安装和维护面偏大。

本轮修改前评估脚本结果：

```text
known error id: 156/235 (66.4%)
BPFIX-UNKNOWN: 79/235
related proof spans: 91/235 (38.7%)
taxonomy agreement: 159/235 (67.7%)
terminal dictionary taxonomy agreement: 199/235 (84.7%)
root pc exact on labeled subset: 88/140 (62.9%)
```

本轮已落实的当前结果：

```text
known error id: 235/235 (100.0%)
BPFIX-UNKNOWN/E000/E099 on replay logs: 0/235
related proof spans: 99/235 (42.1%)
taxonomy agreement: 217/235 (92.3%)
taxonomy macro-F1: 0.858
lowering-artifact recall: 12/24 (50.0%)
verifier-false-positive recall: 6/9 (66.7%)
terminal dictionary taxonomy agreement: 199/235 (84.7%)
root pc exact on labeled subset: 101/140 (72.1%)
root pc within 5 on labeled subset: 120/140 (85.7%)
serde_yaml in Rust workspace: removed
archived Python implementation: removed from maintained tree
object/CFG analysis: feature-gated behind object-analysis
total current diff: net deletion remains >15000 lines
```

这说明当前产品价值不是“完整自动 root cause”，而是：

> 比 raw terminal line 更稳定地给出 structured location、required proof、evidence
> 和 next action；但只有部分 case 有可靠 proof lifecycle。

README、paper 和 CLI 输出都应该围绕这个真实能力收敛。

## 用户真正需要什么

普通 eBPF 用户不是来验证论文 claim 的。他们只想知道：

1. 这是源码问题、环境问题、kernel feature 问题，还是 verifier 复杂度问题？
2. verifier 停在哪里？
3. 它缺什么 proof？
4. 我下一步应该改哪类代码，或者该检查哪个环境条件？
5. 这个建议有多确定？

因此，BPFix 的开源 UX 应该遵守三条原则：

- 没把握时少说，不要编造修复建议。
- 每条 help 必须来自明确的 supported family。
- 不输出 `unknown` 这种对用户没有行动价值的词。

## CLI 输入原则

公开 CLI 应保持一个非常简单的心智模型：

```text
bpfix [OPTIONS] [LOG]
```

这里的 `LOG` 永远是 verifier/build/load log。它可以是一个 positional 文件，也可以省略
后从 stdin 读取：

```bash
bpfix verifier.log
make load 2>&1 | bpfix
sudo bpftool -d prog load xdp.o /sys/fs/bpf/xdp 2>&1 | bpfix
```

默认路径不应该解释为 command runner、benchmark case、Docker environment 或 repo
workspace。BPFix 的核心职责是读取已有日志并解释 verifier reject，默认用户入口不
应该负责执行 loader 命令。

其他能力都必须是显式选项或专门子命令：

- `--format json`：机器可读输出；
- `--object prog.o`：可选 object metadata / experimental source correlation；
- `--docker ...`：如果未来需要 Docker，只能作为显式可选参数，不能改变 positional
  或 stdin 的日志输入语义；
- benchmark/evaluation 相关输入：放到 evaluation 子命令或 dev feature，不进入默认
  positional 参数语义。

换句话说，positional 参数和 stdin 都只表示“这里有一段日志”。这条规则比多做一个
command runner 更重要。

## “不输出 unknown”的设计

不应该再公开输出 `BPFIX-UNKNOWN`。

建议改成两层策略：

### 1. 真实 verifier reject 不允许 generic unknown

对 `bpfix-bench` 235 个 replayable verifier reject，目标是全部输出稳定 error id。
也就是说，CI 里加一个 gate：

```text
bpfix-bench replay logs: error_id must not be BPFIX-UNKNOWN
```

这不代表每个 case 都要有完整 lifecycle span，但至少要有明确的用户分类和安全 next
step。

### 2. malformed / no verifier region 才允许 unsupported fallback

如果输入不是 verifier log，或者没有 terminal verifier error，输出可以是：

```text
error[BPFIX-E000]: no verifier rejection was found in this input
```

但不要叫 unknown。它应该告诉用户怎么重新捕获日志：

```text
help: Re-run the load with bpftool -d or enable libbpf verifier logging.
help: Pass the full stderr from the failing load command, not only the final loader error.
```

`E000` 只能用于“没有足够 verifier 输入”，不能用于真实 verifier reject。

## 先补哪些 error family

从 blind audit sample 和当前 UNKNOWN 文本看，优先补这些 family，比继续做大分析更有用户价值：

| 新 error family | 目标 |
|---|---|
| `BPFIX-E007` alignment proof | 覆盖 `misaligned stack access off ... size ...` |
| `BPFIX-E008` expected pointer/type mismatch | 覆盖 `R1 type=scalar expected=fp`、`expected=pkt/map_value/...` |
| `BPFIX-E010` helper/kfunc argument contract | 覆盖 `Caller passes invalid args into func#...`、helper arg type/refinement |
| `BPFIX-E011` context/program type access | 覆盖 invalid ctx access、wrong attach/program context |
| `BPFIX-E012` dynptr protocol | 保留现有 id，但细分 null slice、invalidated slice、mode mismatch |
| `BPFIX-E013` kfunc/trusted pointer/ref contract | 覆盖 kfunc trusted arg、acquire/release、missing BTF |
| `BPFIX-E014` iterator/lifecycle | 覆盖 iterator create/destroy/read-after-destroy |
| `BPFIX-E015` lock/RCU/IRQ discipline | 覆盖 spin lock、RCU、IRQ state ordering |
| `BPFIX-E016` loader/object/env unsupported opcode | 覆盖 unknown opcode、unsupported JIT/kfunc/helper/kernel feature |
| `BPFIX-E018` verifier limit | 保留现有 id，补 stack depth、state explosion、processed insn variants |

这些 family 不一定一开始都有 related spans。第一步先给出安全、明确、非 unknown 的
diagnostic。

## 去掉 regex/heuristic 的正确方式

不能天真地“完全不用字符串匹配”，因为 verifier 输出本身就是文本。但应该去掉现在这种
散落在多个函数里的 substring classifier。

建议改成：

```text
raw log
  -> LogRegion
  -> TerminalMessage { kind, register, offset, size, helper, expected_type, raw }
  -> DiagnosticCatalog rule
  -> Diagnostic { id, family, confidence, evidence, safe_help }
```

具体改法：

1. 建一个 `terminal.rs`，只负责解析 terminal message。
2. 建一个 `catalog.rs`，用一个中心化表描述 error id、family、required proof、help。
3. 删除 `main.rs::classify()` 和 `diagnostic.rs::infer_obligation()` 的重复规则。
4. 所有 pattern 都必须有 fixture test，至少覆盖 terminal line 和 expected parsed fields。
5. rule 必须声明 evidence requirement。证据不够时，只输出 low-confidence triage，不输出具体 repair。

这样仍然会匹配文本，但它不再是“到处写 regex 形成的黑盒 classifier”，而是一个可测试、
可审计的 diagnostic catalog。

## 降低误导输出

当前 fallback 的危险点是：即使没有分类成功，也会输出 generic proof/help，并把
`failure_class` 默认成 `source_bug`。

建议输出策略：

| 情况 | 输出策略 |
|---|---|
| supported family + enough evidence | 输出 error id、required proof、source span、safe help |
| supported family + weak localization | 输出 error id、required proof、terminal evidence、低置信 span |
| unsupported terminal message | 输出具体 unsupported family id 或 E000，不给源码修复建议 |
| no verifier region | 输出 E000，提示如何重新获取完整 verifier log |
| object/BTF parse fail | 只作为 warning，不影响主诊断 |

JSON 里建议新增：

```json
{
  "confidence": "high | medium | low",
  "diagnostic_kind": "supported | unsupported_input | unsupported_verifier_message",
  "span_confidence": "exact_pc | nearest_source_comment | terminal_line_only | none",
  "help_safety": "repair_hint | triage_only"
}
```

文本输出里也应该显示置信度：

```text
error[BPFIX-E007]: stack access is misaligned
  = confidence: high
  = class: source_bug
  --> prog.bpf.c:42
   = verifier: misaligned stack access off 0+-9+0 size 8
   = required proof: keep 8-byte stack accesses aligned for the verifier
help: Align the stack object or use byte/word accesses that match the proven alignment.
```

低置信时：

```text
error[BPFIX-E000]: no verifier rejection was found in this input
  = confidence: low
help: Re-run the load with bpftool -d and pass the full stderr to bpfix.
```

## 代码量怎么砍

当前统计：

```text
crates/bpfix/src/main.rs         1221 lines
crates/bpfix/src/diagnostic.rs   1216 lines
crates/bpfanalysis/...           large CFG/pass/object surface
old docs/bpfix-py package/tests  removed
net repository change            -15552 lines
```

建议先做结构性减法，而不是继续往 `main.rs` 和 `diagnostic.rs` 里塞 family。

### P0: 产品 CLI 只保留 log-first 主路径

- 已完成：把 benchmark YAML 支持移出默认 runtime path。
- 方案：`bpfix bench-yaml <file>`、`--input-format bench-yaml`，或者 `dev` feature。
- 已完成：默认 `bpfix <log>` 不再尝试把任意输入 parse 成 YAML。
- 已完成：移除 `serde_yaml` 作为普通用户路径依赖。

原因：YAML 是 evaluation convenience，不是用户工作流。它在主路径里会让产品边界变模糊。

### P0: 合并 classifier

- 删除 `classify()` 与 `infer_obligation()` 的重复判断。
- 统一成 `DiagnosticCatalog::classify(TerminalMessage, ParsedTrace) -> DiagnosticSeed`。
- 每个 id 只有一个地方定义 summary、class、required_proof、help。

这会减少代码，也减少“error id 和 required proof 不一致”的风险。

### P1: 把 object/CFG 变成 experimental feature

`--object` 现在有价值，但主要是 metadata，不是完整 source correlation。开源 UX 里应降级：

```text
bpfix --object xdp.o verifier.log
```

可以保留，但文档应写成：

> Experimental: records object CFG metadata and may improve future source correlation.

已完成：object/CFG 已放到 cargo feature：

```text
bpfix default = []
bpfix object-analysis = ["bpfanalysis/object-analysis"]
bpfanalysis default = ["analysis", "object-analysis"]
bpfanalysis object-analysis = ["analysis", "dep:object"]
```

更好的长期结构：

```text
crates/bpfix-core/      log normalize, terminal parser, catalog, renderer
crates/bpfix/           CLI wrapper
crates/bpfanalysis/     research/object/CFG/BTF analysis, optional
```

这样普通用户安装 BPFix 不需要为研究型 CFG/pass 代码付复杂度成本。

### P1: 删除不安全 source-comment heuristics

`looks_like_scalar_guard`、`looks_like_null_check`、`looks_like_stack_initialization`
这类函数会让输出看起来像“找到了 proof lifecycle”，但它们本质上是在读 source
comment 猜语义。

当前实现已经把 proof event 标成不同 evidence kind：

- verifier state / terminal verifier evidence 可以输出强 lifecycle label；
- source comment pattern 只能输出 `nearby source context ...`；
- 同一行同时有 source-comment 和 verifier-state evidence 时，renderer 保留更强的
  verifier-state label。

仍需继续做的约束：

- high-confidence related span 只能来自 verifier state transition 或明确的 source/BTF mapping。
- source comment pattern 只能作为 `span_confidence = nearest_source_comment`。
- 低置信 related span 不要重新写成“proof established/lost”。

这能减少 unsafe help 和 false lifecycle claim。

## 文档和 README 要收敛

README 当前应该调整：

- 保留 `bpfix [LOG]` 的 simple UX。
- 明确 positional 参数和 stdin 都是 verifier/build/load log。
- 删除命令执行入口设想；BPFix 默认不负责执行 loader 命令。
- Docker 必须是 `--docker` 这类显式可选模式；benchmark、object analysis 也只能是
  显式选项或实验功能。
- 明确写：BPFix 是 best-effort diagnostic，不是 automatic root-cause prover。
- support matrix 要标出 `supported / partial / experimental`。
- `--object` 标为 experimental，不承诺完整 BTF-backed source correlation。
- benchmark YAML 放到 evaluation 章节，不放 normal workflow。
- `BPFIX-UNKNOWN` 从文档和输出中消失。

建议新增一个用户页：

```text
docs/user-guide.md
```

内容只讲：

1. 怎么获取 verifier log；
2. 怎么运行 `bpfix`；
3. 怎么理解 confidence；
4. 哪些 error family 支持；
5. 什么时候该检查环境而不是改源码；
6. 如何在 CI/editor 里用 JSON。

## UX 功能建议

### `bpfix doctor`

用于开源用户自查环境：

```bash
bpfix doctor
```

检查：

- kernel version；
- `/sys/kernel/btf/vmlinux` 是否存在；
- `bpftool` 是否可用；
- clang 是否支持 `-target bpf`；
- 当前用户是否有 CAP_BPF/CAP_PERFMON/root；
- `bpfix --object` 是否可用。

这比让用户从 benchmark error 里猜环境问题更实用。

### `bpfix explain BPFIX-E005`

输出某个 error id 的解释、例子和常见修法：

```bash
bpfix explain BPFIX-E005
```

这能让 error catalog 成为开源文档的一部分，而不是只藏在代码里。

## 推荐路线

### Milestone 1: No Unknown / No Unsafe Fallback

目标：真实 verifier reject 不再输出 `BPFIX-UNKNOWN`，fallback 不给错误修复建议。

任务：

- 已完成：引入 `BPFIX-E000` 只处理 no verifier input。
- 已完成：为 79 个 UNKNOWN 分组，优先补 alignment、expected type、helper args、IRQ/lock、kfunc/dynptr。
- 已完成：fallback 不再默认为 `source_bug`。
- 已完成：JSON 增加 `confidence`、`diagnostic_kind`、`help_safety` 和 `span_confidence`。
- 已完成：eval gate 证明 235 replay logs 不输出 `BPFIX-UNKNOWN/E000/E099`。

### Milestone 2: Catalog-First Classifier

目标：去掉散落的 regex/substring classifier。

任务：

- 新增 `terminal.rs` 和 `catalog.rs`。
- 合并 `classify()` / `infer_obligation()`。
- 每个 terminal kind 都有 fixture tests。
- 每个 error id 的 help 都有 safety review。

### Milestone 3: Product CLI Simplification

目标：让普通用户安装和使用更轻。

任务：

- 已完成：YAML 输入移出默认路径。
- 已完成：`--object` 在 README 中标成 experimental enhancement，并放到
  `object-analysis` feature。
- 已完成：README 重写成用户导向，不把 benchmark 放主路径。
- 已完成：新增 `docs/user-guide.md`。

### Milestone 4: Trustworthy Spans

目标：related spans 不再像 proof claim 那样过度自信。

任务：

- 每个 span 增加 `span_confidence`。
- source-comment heuristic span 降级为 context。
- 只有 verifier state/object/BTF 支撑时才输出 `proof_established/proof_lost`。
- blind audit 重新统计 unsafe help。

### Milestone 5: Real User Validation

目标：证明它对开源用户真的有用。

任务：

- 找 20-30 个真实 verifier reject 案例。
- 比较 raw log、BPFix text、BPFix JSON+agent。
- 指标不是 paper accuracy，而是 triage time、是否知道下一步、错误建议率。

## 建议的公开定位

当前最诚实、最有用的公开定位：

> BPFix is a log-first eBPF verifier diagnostic CLI. It turns verifier logs into
> structured, confidence-rated diagnostics with stable error IDs, source/log
> evidence, and safe next steps. It is best-effort: supported families produce
> proof-oriented help; unsupported inputs produce log-collection or triage guidance
> rather than guessed repairs.

中文可以写成：

> BPFix 是一个 log-first 的 eBPF verifier 诊断工具。它读取用户已有的
> bpftool/libbpf/Aya/BCC/CI 日志，输出稳定 error id、证据、置信度和下一步建议。
> 对已支持的 verifier family，它给出 proof-oriented help；对不支持或日志不足的输入，
> 它只给日志获取或 triage 建议，不编造源码修复。

这个定位比“自动 root-cause proof reconstruction”更适合当前实现，也更适合开源用户。
