# BPFix-Test 40-Case Milestone Plan

最后更新：2026-06-17

## 目标

40-case milestone 不是把当前 18 个 case 简单扩容。它的目标是形成一个更可信的
LLM one-shot eBPF 修复挑战集：

- 继续使用 source + raw verifier log 与 source + BPFix structured diagnostic
  两种输入；
- 每个 case 仍然由 `test.py` 判定：编译、verifier load、`bpftool prog run`
  功能返回值都必须正确；
- 新增 case 必须和现有 pointer-cookie/lowering pilot 形成机制差异，不能只是换变量名；
- 40 个全部 admitted 后，重新跑一次同配置 raw/structured full suite，再报告结果。

这个 milestone 只回答“BPFix diagnostic 是否帮助 LLM 修出真实可运行程序”。它不替代
`bpfix-bench/` 的 taxonomy 评测，也不使用 label agreement 当成功标准。

## Admission Gate

一个 case 只有满足以下条件才计入 40 个：

1. `cases/<case_id>/` 目录内只有 case 自己需要的文件：`README.md`、
   `buggy.bpf.c`、`verifier.log`、`structured.json`、`test.py`。
2. `buggy.bpf.c` 在 pinned Linux/BPF 环境中真实 verifier reject。
3. `structured.json` 由当前 BPFix 从同一份 `verifier.log` 生成，且
   `diagnostic_kind == "supported"`，不能输出 `unknown`。
4. `test.py` 至少包含一个功能 oracle；只让 verifier load 成功不算修复成功。
5. runner prompt 不泄露 `test.py` 里的 expected return、success predicate 或
   reference fix。
6. 新 case 的失败机制必须在 README 中说明，且不能与已 admitted case 同构。
7. raw/structured LLM 结果只能在 case admitted 之后统计，不能把单模型跑不过当作唯一
   选样标准。

本地 gate：

```bash
python3 bpfix-test/tools/audit_cases.py
python3 bpfix-test/tools/audit_cases.py --smoke
```

40 个 case 全部 admitted 后必须再跑：

```bash
python3 bpfix-test/tools/run_suite.py --mode raw ...
python3 bpfix-test/tools/run_suite.py --mode structured ...
```

## Diversity Budget

当前 18-case pilot 已经证明 raw log 对 pointer provenance / helper side-effect
场景不够稳定，但分布过于集中。40-case milestone 的配额如下：

| Bucket | 目标数量 | 说明 |
| --- | ---: | --- |
| Existing proof-lifecycle/lowering pilot | 18 | 保留现有 admitted pilot，作为 regression baseline。 |
| Stack and indirect-memory proof | 4 | 未初始化 stack、partial init、helper 间接读、map update value。 |
| Scalar/range/precision proof | 4 | variable offset、signed/unsigned、loop-carried widening、different checked/use value。 |
| Helper contract and environment boundary | 4 | wrong map pointer、wrong helper/map type、tail call/map contract、helper side-effect。 |
| Reference lifecycle variants | 3 | discard 后 submit、double submit、nested reserve cleanup。 |
| Source/correlation and control-flow | 5 | subprog nullability、macro side effect、inline return、multi-branch source span、object/source misleading final line。 |
| Modern protocol seed | 2 | 优先 dynptr/kfunc/ref-like verifier protocol；若本机内核或 headers 不支持，用同等现代 helper/ref protocol 替代。 |

总数：18 + 22 = 40。

约束：

- pointer-cookie/lowering 类型最多占 18/40，新增 22 个不能继续靠同一种 cookie 模式堆数；
- 至少 12 个新增 case 的正确修复需要改变程序结构，而不是删掉一行 cast/mask；
- 至少 10 个新增 case 的 raw verifier final line 不能直接指出完整修复动作；
- 至少 8 个新增 case 应该让“只看源码”很难判断 verifier proof 为什么丢失。

## Planned 22 New Cases

| case id | bucket | 挑战点 | 功能 oracle |
| --- | --- | --- | --- |
| `stack_uninit_branch_001` | stack | 只在一个分支初始化 stack scalar，merge 后读取。 | UDP/TCP 分支返回值不同且修复必须保留分支语义。 |
| `stack_partial_init_helper_001` | stack | struct value 只初始化部分字段后被 helper 间接读取。 | map/ringbuf helper side effect 必须仍发生。 |
| `map_update_uninit_value_001` | stack | `bpf_map_update_elem()` 读取未完全初始化的 stack value。 | map 更新后的返回语义和 helper call 保留。 |
| `map_lookup_uninit_key_001` | stack | map lookup key 从未初始化 stack 读取。 | 修复必须初始化 key 并保留 map lookup 语义。 |
| `map_value_variable_offset_001` | scalar/range | map value offset 由 packet 字段控制，range proof 不足。 | 不同 packet 值访问不同 map slot。 |
| `packet_bounds_ihl_001` | scalar/range | IPv4 IHL 变量影响 L4 offset，bounds proof 不够。 | normal、options、truncated packet 返回值正确。 |
| `packet_checked_use_different_base_001` | scalar/range | check 的 pointer 和最终 dereference 的 pointer 不是同一 verifier value。 | UDP/TCP/truncated 行为保留。 |
| `packet_loop_carried_bounds_001` | scalar/range | loop-carried offset widening 后访问 packet。 | 多段 option/parser 路径返回值正确。 |
| `helper_map_arg_stack_001` | helper contract | helper 第一个参数需要 map pointer，源码传 stack pointer。 | 正确 map lookup 后 packet 行为保留。 |
| `tail_call_wrong_map_type_001` | helper contract | `bpf_tail_call()` 使用非 prog-array map。 | helper call 保留，空 tail-call fallback 返回值正确。 |
| `redirect_map_wrong_type_001` | helper contract | `bpf_redirect_map()` 使用错误 map type。 | 修复后 redirect/fallback 语义明确。 |
| `checksum_helper_bad_arg_001` | helper contract | checksum helper 参数 pointer/size proof 不满足 contract。 | checksum 分支和普通分支返回值正确。 |
| `ringbuf_submit_after_discard_001` | ref lifecycle | discard 后继续 submit 同一个 ref。 | 某分支 discard，另一个分支 submit，不能删除 ringbuf。 |
| `ringbuf_double_submit_001` | ref lifecycle | 同一个 ref 被 submit 两次。 | 只 submit 一次且保留 event 字段。 |
| `ringbuf_nested_ref_cleanup_001` | ref lifecycle | 两个 reserve 后早退路径只释放一个 ref。 | 两个 event 的 release/submit 路径正确。 |
| `subprog_nullability_001` | source/correlation | subprog 返回 nullable pointer，caller 误以为已证明 non-null。 | subprog 调用保留，map 值驱动返回值。 |
| `macro_bounds_side_effect_001` | source/correlation | macro 同时做 bounds check 和 offset update，修复不能删除 side effect。 | macro 路径下 packet offset 行为正确。 |
| `inline_return_packet_001` | source/correlation | inline helper 返回 checked packet pointer，caller 用错 value。 | inline helper 保留，truncated case 正确。 |
| `multi_branch_final_line_mislead_001` | source/correlation | final reject 在 dereference，真实 root cause 在早期 branch proof merge。 | 三条分支的返回值都覆盖。 |
| `btf_line_sparse_macro_001` | source/correlation | 多个 verifier insn 映射到同一源码行，source span 不够。 | 修复不能删掉宏展开里的必要检查。 |
| `dynptr_slice_null_001` | modern protocol | dynptr slice 返回 nullable pointer，未检查即访问。 | 若本机支持 dynptr，检查 helper path；否则替换为 ringbuf/ref protocol。 |
| `kfunc_or_timer_protocol_001` | modern protocol | kfunc/timer/ref-like protocol 需要特定上下文或 release discipline。 | 若本机支持 kfunc/timer，检查 protocol；否则替换为同等 helper/ref protocol。 |

这些名字是设计目标，不是 admission 保证。实现时如果某个现代 helper 受本机内核或
headers 限制无法稳定 smoke，必须用同 bucket、同难度的 case 替换，并在本文档更新。

## Reporting Rules

汇报 40-case 结果时必须分清四种数字：

- admitted case count：通过 audit/smoke 的真实 case 数；
- raw one-shot pass：LLM 看源码 + raw verifier log 的修复成功数；
- structured one-shot pass：同模型看源码 + BPFix JSON 的修复成功数；
- excluded seed：构造过但因为太容易、不稳定、unsupported diagnostic 或 oracle 不充分而未计入的 case。

不能把“构造了 40 个想法”写成“40 个 admitted cases”。只有 audit/smoke 都通过、
并且 `structured.json` 非 unknown 的 case 才能计入。

## 下一步执行顺序

1. 先补 stack/indirect-memory 4 个 case，验证 BPFix 对 stack proof signal 是否够用。
2. 再补 scalar/range 4 个 case；如果 BPFix 输出 unknown，优先改 diagnostic engine，
   不靠更宽的 terminal-message regex。
3. 补 helper/ref/source-correlation case，每 4 到 6 个 case 做一次 audit/smoke commit。
4. 达到 40 个后，启动 Qwen27B raw/structured full-suite run，并把 summary hash 和
   per-case 表写入 `pilot-results.md`。
