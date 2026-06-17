# BPFix-Test Clean60 Benchmark Protocol

最后更新：2026-06-17

`clean60` 是 `bpfix-test` 的论文主 benchmark 目标：60 个新的、无污染的、
source-first eBPF verifier-reject repair cases。当前仓库已经有 `dev40`，但
`dev40` 在 case、prompt、diagnostic 和 oracle 开发中被反复使用，只能作为
calibration/dev evidence，不能作为 clean benchmark。

本协议把 venue bar 转成工程 gate：NeurIPS checklist 强调可复现性、数据集/
基准构造、限制和资产说明；NeurIPS Evaluations & Datasets reviewer guidelines
强调数据来源、质量控制、指标、维护和可用性；OSDI artifact 口径强调可运行、
可复现、可验证的 artifact。对应到这里，`clean60` 必须是冻结 split、可执行 oracle、
完整 provenance、多模型评测和污染审计共同成立的 benchmark。

参考：

- NeurIPS Paper Checklist:
  <https://neurips.cc/public/guides/PaperChecklist>
- NeurIPS 2026 Evaluations & Datasets Reviewer Guidelines:
  <https://neurips.cc/Conferences/2026/EvaluationsDatasetsReviewerGuidelines>
- NeurIPS 2026 Call for Evaluations & Datasets:
  <https://neurips.cc/Conferences/2026/CallForEvaluationsDatasets>
- OSDI 2026 Call for Artifacts:
  <https://www.usenix.org/conference/osdi26/call-for-artifacts>

## 非目标

`clean60` 不是：

- 从 `bpfix-bench` 的 235 个 replay logs 里抽样；
- 从当前 `dev40` 里挑 60 个、复制 60 个、或换名扩容；
- 用 Qwen27B 跑一遍后只保留 raw 失败、structured 成功的 case；
- 用 label agreement、error id、regex 命中率当修复成功；
- 只证明 BPFix 能分类 verifier log。

`clean60` 要回答的是：

> 在模型、prompt、BPFix diagnostic 和 case split 冻结后，BPFix structured
> diagnostic 是否能稳定提高 LLM 对真实 eBPF verifier reject 的一次修复成功率？

## Split 规则

当前 split 文件：

- `splits/dev40.txt`：现有 40 个 calibration cases；
- `splits/clean60.txt`：clean benchmark 占位，当前必须为空，直到 60 个新 case
  admission 完成。
- `splits/*.manifest.json`：split 的机器可审计元数据。`clean60.manifest.json`
  必须在首轮 clean run 前 frozen，并包含每个 case 的 source category、bucket、
  program type、independent review、oracle obligation 和 case hash。

`clean60` admission gate：

```bash
python3 bpfix-test/tools/audit_splits.py \
  --split bpfix-test/splits/clean60.txt \
  --manifest bpfix-test/splits/clean60.manifest.json \
  --profile clean60 \
  --expected-count 60 \
  --disallow-overlap bpfix-test/splits/dev40.txt \
  --audit-cases --smoke
```

这个命令在 `clean60` 填满前应该失败。只有它通过后，才能把 `clean60` 作为主
benchmark 运行。`run_suite.py --split bpfix-test/splits/clean60.txt` 对空 split
也会失败，不会把空 split 解释成“全部 case”。
`audit_splits.py --profile clean60` 会内置比较 `dev40.txt` 的 case id、case hash
和 `buggy.bpf.c` hash；命令行里的 `--disallow-overlap` 是显式记录，不是唯一防线。
这个 hash gate 只能阻止精确复制或改名复制；语义近重复仍必须由 provenance 记录和
independent review 拒绝。

## 污染控制

`clean60` 必须满足：

1. 所有 case id 不在 `dev40.txt` 中。
2. 所有 case 在第一次 LLM clean run 前 admitted；之后不能因为模型结果删 case。
3. prompt、runner、BPFix commit、model config 和 oracle 都在 clean run 前冻结。
4. 如果 freeze 后修 oracle bug，必须记录 bug、影响范围，并从头重跑所有 baseline。
5. 不允许把 reference fix、oracle expected return、success predicate、README hints
   放进 prompt。
6. 不允许用 raw/structured model result 作为 admission 条件。可以记录 seed
   exclusion，但 exclusion 原因必须是 verifier 接受、不稳定、不可复现、oracle 不足、
   或当前 BPFix unsupported，而不是“模型修得太容易/太难”。
7. 独立 reviewer 至少审核每个 case 的 bug、oracle 覆盖和 provenance。

## Case 格式

保持当前单文件约定，不引入 YAML：

```text
cases/<case_id>/
  README.md
  buggy.bpf.c
  verifier.log
  structured.json
  test.py
```

`buggy.bpf.c` 是唯一给模型的源文件。`verifier.log` 是 raw baseline 输入。
`structured.json` 是 BPFix 输入。`test.py` 是唯一自动 oracle。

`README.md` 只给人类 reviewer 使用，不进入 prompt。它必须说明：

- 来源：real project seed、production-shaped synthetic、或 minimized upstream-style
  reproducer；
- 为什么这是 verifier reject；
- 正确修复必须保留的功能语义；
- 如果有 helper/proof predicate，为什么 runtime oracle 不能直接观察该义务。

## Oracle 标准

每个 case 的成功条件：

1. 候选必须是完整 BPF C 源码；
2. 编译成功；
3. verifier load 成功；
4. `bpftool prog run` 功能返回值正确；
5. 如果 helper/protocol side effect 是核心语义，oracle 必须尽量直接检查可观察
   结果；只有无法直接观察时，才允许使用 successful verifier log 的 proof predicate；
6. verifier-success predicate 必须是辅助 oracle，并在 README 中解释其必要性；
7. oracle 不要求候选和某个 reference fix 文本相同，ground truth 是语义约束和可执行
   行为，不是唯一补丁。

## 60 个 case 的目标组成

`clean60` 应该覆盖真实生产开发会遇到的差异，而不是堆同构 puzzle：

| 类型 | 目标数量 | 要点 |
| --- | ---: | --- |
| Proof lifecycle | 18 | proof 建立、丢失、merge 后拒绝；final verifier line 误导。 |
| Source/object correlation | 12 | macro、inline、subprog、多 section、稀疏 line info、Rust/Aya-style 名字。 |
| Modern BPF protocol | 15 | dynptr、ringbuf/ref lifecycle、kfunc/timer/iterator/rbtree/sleepable 规则。 |
| Helper and memory contract | 8 | stack/map/packet memory 作为 helper 间接参数、初始化和长度证明。 |
| Environment/config boundary | 7 | helper/kfunc unavailable、wrong prog type、attach mismatch、missing BTF、feature gate。 |

约束：

- XDP 不能超过 25/60；
- 至少 20/60 源于真实项目结构或真实 bug 形态的 minimized reproducer；
- 至少 20/60 的正确修复需要保留 helper side effect 或 map/ringbuf state；
- 至少 15/60 包含 source correlation 难点，而不是只修最后一行；
- 至少 10/60 是 modern BPF protocol 或 environment/config boundary；
- 每个 bucket 至少包含 3 个 raw verifier final line 不能直接推出完整修复的 case。

## Baseline 和模型矩阵

主表至少报告：

| 输入模式 | 模型看到什么 | 目的 |
| --- | --- | --- |
| source-only | `buggy.bpf.c` | 测试只看代码能否猜出修法。 |
| raw | `buggy.bpf.c` + `verifier.log` | 真实开发者常见输入。 |
| trimmed-raw | `buggy.bpf.c` + 自动截取 verifier region | 控制 structured 是否只是更短。 |
| structured | `buggy.bpf.c` + `structured.json` | 测试 BPFix proof signal 的贡献。 |

至少跑 3 个模型族或大小档位，避免只对 Qwen27B 调参：

- Qwen/llama.cpp 本地量化模型；
- 一个 Llama-family 模型；
- 一个不同训练族的模型，例如 DeepSeek、Mistral、Gemma 或云端闭源模型。

`run_suite.py` 已支持 `--model`、`--base-url`、`--model-path`、
`--model-sha256`、`--llama-cpp-dir` 和 `--split`，结果会记录 commit、dirty、
toolchain、prompt hash、prompt length、model config 和 server metadata。

示例：

```bash
python3 bpfix-test/tools/run_suite.py \
  --split bpfix-test/splits/clean60.txt \
  --expected-count 60 \
  --mode raw \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M

python3 bpfix-test/tools/run_suite.py \
  --split bpfix-test/splits/clean60.txt \
  --expected-count 60 \
  --mode structured \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M
```

## 报告规则

论文或 README 中必须同时报告：

- split 文件和 git commit；
- 所有 case id；
- 每个模型、每个输入模式的 pass/total；
- 每个 fail 的 oracle stage：model error、extract、compile、verifier load、
  functional oracle、auxiliary proof predicate；
- prompt chars、diagnostic chars、max tokens、temperature；
- model digest 或明确说明未记录；
- kernel、clang、bpftool、libbpf、llama.cpp commit；
- seed exclusion ledger 和 reviewer audit 状态。

不能报告：

- 把 `dev40` 的 9/40、23/40 当作 clean benchmark；
- 把 post-hoc 删除 case 后的新 denominator 当主结果；
- 只报告 structured 成功 case；
- 把 proof predicate failure 直接说成“功能错误”，必须区分功能 oracle 和辅助
  proof predicate。

## 当前状态

截至 2026-06-17：

- `dev40` 已完成：40/40 audit pass，40/40 smoke pass；
- `dev40` Qwen27B 结果：raw 9/40，structured 23/40；
- `clean60` 尚未 admitted：0/60；
- clean benchmark 主结果尚不存在。

下一步不是把 `dev40` 扩写成 paper claim，而是按本协议新增 60 个无重叠 heldout
case，freeze 后再跑 source-only/raw/trimmed-raw/structured 和多模型矩阵。
