# BPFix-Test 40-Case Milestone Record

最后更新：2026-06-17

## 目标

40-case milestone 不是把当前 18 个 case 简单扩容。它的目标是形成一个更可信的
LLM one-shot eBPF 修复挑战集：

- 继续使用 source + raw verifier log 与 source + BPFix plain-text diagnostic
  两种输入；
- 每个 case 仍然由 `test.py` 判定：编译、verifier load、`bpftool prog run`
  功能返回值都必须正确；
- 新增 case 必须和现有 pointer-cookie/lowering pilot 形成机制差异，不能只是换变量名；
- 40 个全部 admitted 后，重新跑一次同配置 raw/bpfix full suite，再报告结果。

这个 milestone 只回答“BPFix diagnostic 是否帮助 LLM 修出真实可运行程序”。它不替代
`bpfix-bench/` 的 taxonomy 评测，也不使用 label agreement 当成功标准。

## 当前状态

截至 2026-06-17，40-case milestone 已经 admission 完成：

- admitted case count：40/40；
- 原始 pilot：18 个；
- 本轮新增 admitted case：22 个；
- `python3 bpfix-test/tools/audit_cases.py`：40/40 pass；
- `python3 bpfix-test/tools/audit_cases.py --smoke`：40/40 pass；
- 40-case Qwen27B raw/bpfix full-suite：已完成第一轮；
- raw verifier log：9/40 pass = 22.5%；
- BPFix diagnostic：23/40 pass = 57.5%。

所以当前能声明的是“40 个真实 verifier-reject repair case 已经可运行并通过
oracle smoke，并且第一轮 Qwen27B repair run 已经完成”。不能把 18-case pilot 的
`5/18`、`18/18` 数字外推成 40-case 结果；40-case 的真实结果是 `9/40` 和 `23/40`。

## Admission Gate

一个 case 只有满足以下条件才计入 40 个：

1. `cases/<case_id>/` 目录内只有 case 自己需要的文件：`README.md`、
   `buggy.bpf.c`、`verifier.log`、`diagnostic.txt`、`test.py`。
2. `buggy.bpf.c` 在 pinned Linux/BPF 环境中真实 verifier reject。
3. `diagnostic.txt` 由当前 BPFix 从同一份 `verifier.log` 生成，且
   包含 supported diagnostic，不能输出 unknown。
4. `test.py` 至少包含一个功能 oracle；只让 verifier load 成功不算修复成功。
5. runner prompt 不泄露 `test.py` 里的 expected return、success predicate 或
   reference fix。
6. 新 case 的失败机制必须在 README 中说明，且不能与已 admitted case 同构。
7. raw/bpfix LLM 结果只能在 case admitted 之后统计，不能把单模型跑不过当作唯一
   选样标准。

本地 gate：

```bash
python3 bpfix-test/tools/audit_cases.py
python3 bpfix-test/tools/audit_cases.py --smoke
```

40 个 case 全部 admitted 后必须再跑：

```bash
python3 bpfix-test/tools/run_suite.py --mode raw ...
python3 bpfix-test/tools/run_suite.py --mode bpfix ...
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

实际 40-case BPFix diagnostic 分布如下：

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

`BPFIX-E006` 仍是最大单类，因为原始 18-case pilot 保留了较多 pointer-cookie /
lowering case；新增 22 个主要补了 dynptr、ringbuf lifecycle、map-value bounds、
wrong-base packet proof、helper contract、subprogram nullability 和 stale packet
pointer side effect。

## Actual 22 New Cases

| case id | primary bucket | 挑战点 | oracle focus |
| --- | --- | --- | --- |
| `dynptr_slice_stack_buffer_001` | modern protocol / indirect memory | dynptr slice fallback buffer 比请求长度短，helper 间接读越界。 | 修复必须扩大 stack buffer 或改 length，且 dynptr path 保留。 |
| `dynptr_slice_missing_null_check_001` | modern protocol / null proof | dynptr slice 返回 nullable memory，未检查直接访问。 | 修复必须检查 slice 结果并保留 IP ethertype 行为。 |
| `dynptr_uninitialized_slice_arg_001` | modern protocol / initialization | dynptr slice 使用未初始化 stack 参数。 | 修复必须初始化 helper 参数且不删除 dynptr helper path。 |
| `ringbuf_submit_after_discard_001` | reference lifecycle | discard 后继续 submit 同一 ringbuf record。 | 修复必须让 discard/submit 路径互斥。 |
| `packet_eth_off_by_one_001` | packet bounds | Ethernet header 检查少 1 字节，final line 只看到字段读取。 | 修复必须正确覆盖 truncated frame。 |
| `packet_ihl_udp_undercheck_001` | scalar/range / packet bounds | IPv4 IHL 变量决定 UDP offset，bounds proof 不足。 | normal、options、truncated packet 返回值都正确。 |
| `map_value_index_guard_oob_001` | map-value bounds | check 与实际 map-value index 范围不匹配。 | 不同 index 路径访问正确 map slot。 |
| `helper_map_arg_stack_001` | helper contract | map helper 第一个参数需要 map pointer，源码传 stack pointer。 | 修复必须保留 map lookup 和 packet 行为。 |
| `helper_csum_diff_stack_len_001` | helper contract / indirect memory | checksum helper 读取 stack buffer 的长度超过初始化/有效范围。 | 修复必须满足 helper memory contract。 |
| `ringbuf_double_submit_001` | reference lifecycle | 同一 ringbuf record submit 两次。 | 修复必须只 release 一次且保留 event 字段。 |
| `ringbuf_nested_reserve_leak_001` | reference lifecycle | 两个 reserve 后早退路径释放不完整。 | 修复必须覆盖 nested cleanup。 |
| `dynptr_stack_copy_001` | modern protocol / object state | dynptr object 被普通 stack copy 破坏 verifier object protocol。 | 修复必须保留 dynptr helper usage。 |
| `subprog_map_value_null_001` | source correlation / null proof | subprog 返回 nullable map value，caller 误以为 non-null。 | subprog 调用、map 驱动返回值都保留。 |
| `xdp_adjust_tail_stale_001` | helper side effect / provenance | `bpf_xdp_adjust_tail()` 后继续用旧 packet pointer。 | 修复必须重新获取 packet pointer。 |
| `perf_event_packet_payload_001` | helper contract / packet memory | perf-event helper 从 packet payload 读过未证明范围。 | 修复必须先证明 payload memory。 |
| `packet_macro_payload_undercheck_001` | source correlation / macro | macro/inline 风格 payload check 少算字段长度。 | 修复不能删除 macro side effect。 |
| `map_value_signed_index_001` | scalar/range / map-value bounds | signed index 下界未证明，map-value offset 可能为负。 | 修复必须同时约束 signed lower/upper bound。 |
| `dynptr_slice_short_mem_001` | modern protocol / object bounds | dynptr slice 返回短 object 后访问 2 字节字段越界。 | 修复必须请求足够长 slice 并检查 null。 |
| `subprog_adjust_tail_stale_001` | source correlation / side effect | stale packet pointer 藏在 subprogram 后使用。 | 修复必须理解 helper side effect 跨 subprog。 |
| `packet_checked_wrong_base_001` | proof lifecycle / wrong base | 检查了一个 pointer，最终 dereference 另一个 verifier value。 | 修复必须让 check/use 使用同一 base。 |
| `ringbuf_nested_missing_null_001` | reference lifecycle / null proof | nested reserve 中第二个 record 未检查 null。 | 修复必须释放第一个 record 并检查第二个。 |
| `ringbuf_stack_discard_001` | helper contract | 把 stack pointer 当作 ringbuf record discard。 | 修复必须只 discard 真正 reserved record。 |

## Initial Candidate List

下面是 milestone 开始时的候选设计列表，不是最终 admission 结果。实际 admitted
case 以 `Actual 22 New Cases` 为准；没有 admission 的候选要么 verifier 接受、
要么当前 BPFix 输出 unsupported/unknown，要么在本机 pinned 环境下不稳定。

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

## Excluded Seeds

本轮明确排除的 seed：

| seed | 排除原因 |
| --- | --- |
| `stack_uninit_branch_001` | 6.15 环境 verifier 接受，不能作为 reject case。 |
| `map_update_uninit_value_001` | verifier 接受。 |
| `map_lookup_uninit_key_001` | verifier 接受。 |
| `tail_call_wrong_map_type_001` | verifier reject，但当前 BPFix extractor 把日志判成 `unsupported_input`；应先改 engine 再 admitted。 |
| `stack_signed_index_001` | verifier 接受。 |
| `xdp_map_action_range_001` | verifier 接受。 |

## Reporting Rules

汇报 40-case 结果时必须分清四种数字：

- admitted case count：通过 audit/smoke 的真实 case 数；
- raw one-shot pass：LLM 看源码 + raw verifier log 的修复成功数；
- bpfix one-shot pass：同模型看源码 + BPFix diagnostic 的修复成功数；
- excluded seed：构造过但因为太容易、不稳定、unsupported diagnostic 或 oracle 不充分而未计入的 case。

不能把“构造了 40 个想法”写成“40 个 admitted cases”。只有 audit/smoke 都通过、
并且 `diagnostic.txt` 非 unknown 的 case 才能计入。

## 下一步执行顺序

1. 针对 bpfix mode 17 个失败 case 改进 BPFix repair-useful diagnostic，优先处理
   dynptr edge cases、stack/helper memory contract、signed range lower-bound、
   wrong-base packet checks、map-value proof predicate 和 ringbuf multi-reference
   lifecycle side effects。
2. 补 trimmed raw-log baseline，判断 BPFix 的收益来自 proof signal 还是日志压缩。
3. 用至少一个非 Qwen 模型重复 40-case run，降低单模型 admission bias。
4. 让独立 reviewer 审核每个 case 的 bug、oracle 和 structured signal 是否充分。
5. 按 [clean60.md](clean60.md) 新增 60 个无重叠 heldout cases，作为 paper 主
   benchmark；新增 case 优先补 environment/config boundary、kfunc/timer/iterator/
   rbtree 等当前 40-case 尚未覆盖充分的现代协议。
