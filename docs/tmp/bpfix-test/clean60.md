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
- 用 Qwen27B 跑一遍后只保留 raw 失败、bpfix diagnostic 成功的 case；
- 用 label agreement、error id、regex 命中率当修复成功；
- 只证明 BPFix 能分类 verifier log。

`clean60` 要回答的是：

> 在模型、prompt、BPFix diagnostic 和 case split 冻结后，BPFix plain-text
> diagnostic 是否能稳定提高 LLM 对真实 eBPF verifier reject 的一次修复成功率？

## Split 规则

当前 split 文件：

- `splits/dev40.txt`：现有 40 个 calibration cases；
- `splits/real-seed-candidates.txt`：real-project seed staging split。它配套
  `real-seed-candidates.manifest.json` 做 candidate-level provenance、review、
  oracle obligation 和 fingerprint 审计，但不是 clean benchmark denominator；
- `splits/clean60.txt`：clean benchmark 占位，当前必须为空，直到 60 个新 case
  admission 完成。
- `splits/*.manifest.json`：split 的机器可审计元数据。`clean60.manifest.json`
  必须在首轮 clean run 前 frozen，并包含每个 case 的 source category、bucket、
  program type、independent review、oracle obligation、provenance 和 case hash。
- `splits/*.prompts.json`：本地 frozen prompt artifact，已被 gitignore；生成后
  用路径和 hash 记录进实验日志或 artifact bundle，但不要让它改变 clean run 的
  git dirty 状态。

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
和 `buggy.bpf.c` hash。若被比较 split 有 sibling manifest，审计使用 manifest 里的
记录 hash 作为污染基线，而不是只依赖当前 live 文件。命令行里的
`--disallow-overlap` 是显式记录，不是唯一防线。
除了 exact hash，`audit_splits.py` 还会对 candidate/clean60 的 `buggy.bpf.c`
做 normalized token-shingle 近重复检查：当前 split 内部、`dev40` 和
`bpfix-bench/cases/**/*.c` 都会进入比较。当前 fail 条件是 Jaccard >= 0.82 或
containment >= 0.92，普通变量名、数字和字符串会归一化，BPF helper、program
action、协议常量和宏体 token 会保留。这个 gate 能挡住复制、改名、常见轻微包装和
boilerplate 级改写；更高层语义近重复仍必须由 provenance 记录和 independent review
拒绝。
审计 `dev40.txt` 本身也必须携带 `dev40.manifest.json`，否则 frozen fingerprint
baseline 不成立。

real-project seed 候选可以先用较轻的 candidate gate 预审；这个 gate 只证明候选
具备进入 clean60 的基本 provenance/review/oracle 条件，不产生论文主结果：

```bash
make bpfix-test-real-seed-candidate-gate
```

正式论文结果还必须通过 paper gate，它把 split admission 和 prompt freeze 绑定起来：

```bash
make bpfix-test-clean60-paper-gate \
  PROMPT_MANIFEST=bpfix-test/splits/clean60.prompts.json
```

`clean60.prompts.json` 必须来自干净 worktree，验证 prompt manifest 时当前
checkout 也必须是干净的；带 `dirty: true` 的 prompt manifest 只能用于本地
dry-run，不能作为 paper-grade 结果依据。

## 污染控制

`clean60` 必须满足：

1. 所有 case id 不在 `dev40.txt` 中。
2. 所有 case 在第一次 LLM clean run 前 admitted；之后不能因为模型结果删 case。
3. split、case fingerprints、prompt manifest、runner、BPFix commit、model config
   和 oracle 都在 clean run 前冻结。
4. 如果 freeze 后修 oracle bug，必须记录 bug、影响范围，并从头重跑所有 baseline。
5. 不允许把 reference fix、oracle expected return、success predicate、README hints
   放进 prompt。
6. 不允许用 raw/bpfix model result 作为 admission 条件。可以记录 seed
   exclusion，但 exclusion 原因必须是 verifier 接受、不稳定、不可复现、oracle 不足、
   或当前 BPFix unsupported，而不是“模型修得太容易/太难”。
7. 独立 reviewer 至少审核每个 case 的 bug、oracle 覆盖和 provenance。
8. admission gate 会扫描本地 `bpfix-test/results/**/summary.json`；任何已经出现在
   本机 prior LLM run 里的 case id 都不能进入 clean60。

`clean60.manifest.json` 必须把这些原则写成机器可审计字段：

- `admission_policy.result_blind_case_selection: true`；
- `admission_policy.admitted_before_first_clean_run: true`；
- `admission_policy.prompt_manifest_required: true`；
- `selection_protocol` 记录 case source、admission order、review、model-result
  blinding 和 near-duplicate policy；
- `candidate_seed_ledger[]` 中每个 candidate seed 必须有 `seed`、`decision`、
  `decision_made_before_model_eval: true`、`model_result_used: false` 和 `notes`；
  admitted seed 必须一一覆盖 split 中的 case id，excluded seed 必须给出允许的
  `reason`；
- `seed_exclusion_ledger[]` 可以额外记录被排除 seed 的详细解释；每个 exclusion
  必须有 `seed`、允许的 `reason`、`notes`，并且 `model_result_used: false`；
- 每个 case 必须有 `review`、`provenance` 和 `oracle_obligation` 对象。
  `review.not_seen_in_prior_eval` 指这个 case 没有被本项目先前的 prompt tuning、
  diagnostic development 或 LLM evaluation 使用；它不声称模型预训练中从未见过
  相关公开代码。
- 每个 case 必须有 `challenge_flags` 对象：
  `source_correlation_difficulty`、`misleading_final_line` 和
  `semantic_duplicate_reviewed`。其中 `semantic_duplicate_reviewed` 必须为
  `true`，表示独立 reviewer 已检查该 case 不是对 dev40、bpfix-bench 或同 split
  其他 case 的语义近重复。

允许的 exclusion reasons 是：`verifier_accepts`、`unstable`、
`not_reproducible`、`oracle_insufficient`、`bpfix_unsupported`、
`duplicate_or_near_duplicate`、`out_of_scope`、`license_unclear`。

每个 clean60 case 的 `oracle_kind` 至少包含 `compile` 和 `verifier_load`，并且
至少包含一种语义 oracle：`bpftool_prog_run`、`attach_or_runtime`、
`environment_config` 或 `custom_oracle`。这允许 LSM、tracepoint、cgroup 和
environment/config boundary cases 使用 attach/runtime 或配置型 oracle，而不是被
强行塞进 `bpftool prog run`。
当 admission gate 带 `--audit-cases` 运行时，manifest 里的 oracle 声明还会和
`test.py` 交叉检查：`bpftool_prog_run` 必须真的有 functional tests，
`proof_predicate` 必须有 `required_success_predicates`，helper/state obligation
必须有 success substring 或 predicate。这样避免 manifest 声称有强 oracle，但
实际 `test.py` 只做编译或 smoke。

`source_category: real_project_seed` 必须有结构化 upstream provenance：
`provenance.upstream_project`、`provenance.upstream_ref`、
`provenance.upstream_path`、`provenance.upstream_license` 和
`provenance.upstream_file_sha256`。`upstream_ref` 必须是 pinned 40-hex commit；
`upstream_file_sha256` 必须是该 commit 下 `upstream_path` 文件内容的 sha256。
admission gate 会在本地 upstream checkout 上验证 commit、path、SPDX license 和
hash。默认在当前仓库的 sibling 目录查找 upstream repo；如果 artifact 环境把
upstream repos 放在其他目录，设置 `BPFIX_TEST_UPSTREAM_ROOT=/path/to/repos`。
本地 checkout 的任一 git remote 必须匹配 `upstream_project`，`source` 必须是指向
同一 commit/path 的 canonical GitHub/GitLab blob URL，不能只把真实 URL 塞进 query
string 或注释文本。
`clean60` 的 60 个 case 必须全部是 `real_project_seed`，也就是都必须有上述
upstream project/ref/path/license/hash provenance。`minimized_upstream_style`、
`production_shaped_synthetic` 或 clean-room synthetic 可以用于 dev/calibration，
但不能进入 paper-grade clean60。

## Case 格式

保持当前单文件约定，不引入 YAML：

```text
cases/<case_id>/
  README.md
  buggy.bpf.c
  verifier.log
  diagnostic.txt
  test.py
```

`buggy.bpf.c` 是唯一给模型的源文件。`verifier.log` 是 raw baseline 输入。
`diagnostic.txt` 是 BPFix plain-text diagnostic 输入。`test.py` 是唯一自动 oracle。

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
- 60/60 必须是有 upstream project/ref/path/license provenance 的
  `real_project_seed`；
- 至少 20/60 的正确修复需要保留 helper side effect 或 map/ringbuf state；
- 至少 15/60 包含 source correlation 难点，而不是只修最后一行；
- 至少 10/60 是 modern BPF protocol 或 environment/config boundary；
- 每个 bucket 至少包含 3 个 raw verifier final line 不能直接推出完整修复的 case。

这些约束不只是文档要求：`audit_splits.py --profile clean60` 会检查
`challenge_flags.source_correlation_difficulty` 的全局计数、每个 bucket 的
`challenge_flags.misleading_final_line` 计数，以及每个 case 的
`semantic_duplicate_reviewed: true`。

## Baseline 和模型矩阵

主表至少报告：

| 输入模式 | 模型看到什么 | 目的 |
| --- | --- | --- |
| source-only | `buggy.bpf.c` | 测试只看代码能否猜出修法。 |
| raw | `buggy.bpf.c` + `verifier.log` | 真实开发者常见输入。 |
| trimmed-raw | `buggy.bpf.c` + 自动截取 verifier region | 控制 BPFix 提升是否只是更短。 |
| bpfix | `buggy.bpf.c` + `diagnostic.txt` | 测试 BPFix proof signal 的贡献。 |

至少跑 3 个模型族或大小档位，避免只对 Qwen27B 调参：

- Qwen/llama.cpp 本地量化模型；
- 一个 Llama-family 模型；
- 一个不同训练族的模型，例如 DeepSeek、Mistral、Gemma 或云端闭源模型。

`run_suite.py` 已支持 `--model`、`--base-url`、`--model-path`、
`--model-sha256`、`--llama-cpp-dir` 和 `--split`，结果会记录 commit、dirty、
toolchain、prompt hash、prompt length、model config 和 server metadata。
每个失败结果还会记录 `failure_stage`，把 model call、源码抽取、编译、
verifier load、功能 oracle 和辅助 proof predicate 分开。

在第一次 clean model run 前，先冻结 prompt manifest：

```bash
python3 bpfix-test/tools/prompt_manifest.py \
  --split bpfix-test/splits/clean60.txt \
  --expected-count 60 \
  --output bpfix-test/splits/clean60.prompts.json
```

freeze 后用同一个工具验证当前 checkout 仍然生成相同 prompts：

```bash
python3 bpfix-test/tools/prompt_manifest.py \
  --split bpfix-test/splits/clean60.txt \
  --expected-count 60 \
  --verify bpfix-test/splits/clean60.prompts.json
```

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
  --mode bpfix \
  --base-url http://127.0.0.1:18080/v1 \
  --model Qwen.Qwen3.6-27B.f16.gguf.Q4_K_M
```

## Result Integrity Gate

每个模型的一组 clean60 结果必须在报告前通过 `make bpfix-test-result-gate`。
这个 Makefile gate 会先运行 clean60 admission gate 和 prompt gate，再调用底层
`audit_results.py` 读取 `summary.json`，检查：

- 所有 summary 来自同一个 `clean60.txt` hash 和 60 个 case；
- source-only/raw/trimmed-raw/bpfix 四个模式都存在；
- 四个模式的 case 顺序一致，不能混入 dev40、单 case debug 或旧 split；
- 每个 result 的 prompt hash、prompt length、source length 和 diagnostic length
  都匹配冻结的 prompt manifest；
- prompt manifest 不是 dirty worktree 产物；
- 四个模式来自 prompt manifest 冻结的同一个 git commit；
- 四个模式使用同一语义模型配置和工具链 fingerprint；绝对路径、server URL
  和 hostname 只作为 provenance，不作为跨机器 equality key；
- 同一模型矩阵使用相同 temperature、max tokens 和 timeout run budget；
- 每个模型结果记录稳定模型 digest，至少本地模型必须通过 `--model-sha256`
  或 `LLM_MODEL_SHA256` 写入 64 位 hex SHA-256；
- 正式结果不是 dirty worktree 产物；
- `prompt_written` dry-run 不能当 benchmark result；
- 每个失败都有机器可读的 `failure_stage`。

底层 result-audit 工具示例，仅用于调试单个审计步骤，不能单独作为正式报告入口：

```bash
python3 bpfix-test/tools/audit_results.py \
  --split bpfix-test/splits/clean60.txt \
  --expected-count 60 \
  --prompt-manifest bpfix-test/splits/clean60.prompts.json \
  --required-mode source-only \
  --required-mode raw \
  --required-mode trimmed-raw \
  --required-mode bpfix \
  /path/to/source-only/summary.json \
  /path/to/raw/summary.json \
  /path/to/trimmed-raw/summary.json \
  /path/to/bpfix/summary.json
```

正式 Makefile 入口：

```bash
make bpfix-test-result-gate RESULT_SUMMARIES='\
  /path/to/source-only/summary.json \
  /path/to/raw/summary.json \
  /path/to/trimmed-raw/summary.json \
  /path/to/bpfix/summary.json' \
  PROMPT_MANIFEST=bpfix-test/splits/clean60.prompts.json
```

正式 clean result 必须使用 Makefile 组合 gate，不能只跑底层 `audit_results.py`
后就报告。

## 报告规则

论文或 README 中必须同时报告：

- split 文件和 git commit；
- prompt manifest 路径、hash 和验证输出；
- 所有 case id；
- 每个模型、每个输入模式的 pass/total；
- 每个 fail 的 oracle stage：model error、extract、compile、verifier load、
  functional oracle、auxiliary proof predicate；
- prompt chars、diagnostic chars、max tokens、temperature；
- model digest；缺少 digest 的运行不能进入 clean60 主结果；
- kernel、clang、bpftool、libbpf、llama.cpp commit；
- seed exclusion ledger 和 reviewer audit 状态。
- result gate 的输入 summary 路径和输出 JSON。

不能报告：

- 把 `dev40` 的 9/40、23/40 当作 clean benchmark；
- 把 post-hoc 删除 case 后的新 denominator 当主结果；
- 只报告 bpfix diagnostic 成功 case；
- 把 proof predicate failure 直接说成“功能错误”，必须区分功能 oracle 和辅助
  proof predicate。

## 当前状态

截至 2026-06-17：

- `dev40` 已完成：40/40 audit pass，40/40 smoke pass；
- `dev40` Qwen27B 结果：raw 9/40，bpfix diagnostic 23/40；
- `clean60` 尚未 admitted：0/60；
- clean benchmark 主结果尚不存在。

下一步不是把 `dev40` 扩写成 paper claim，而是按本协议新增 60 个无重叠 heldout
case，freeze 后再跑 source-only/raw/trimmed-raw/bpfix 和多模型矩阵。
