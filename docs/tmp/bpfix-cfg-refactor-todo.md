# BPFix CFG Refactor Todo

目标：按理想架构重构当前实现，让 `bpfanalysis` 保持底层分析库形态，让 `bpfix` 承载诊断规则，并让 `--object` 真正走到 object -> instruction stream -> `ProgramCFG` 的路径。

## Todo

- [x] 从 `bpfanalysis` 移除 BPFix 产品规则。
- [x] 在 `bpfanalysis` 暴露中性的 verifier log facts，而不是 `BPFIX-*` 诊断。
- [x] 在 `bpfanalysis` 增加 object 读取和 CFG summary API。
- [x] 在 `bpfix` 增加 diagnostic 模块，承载 required-proof、proof lifecycle、repair hint、taxonomy。
- [x] 让 `bpfix --object prog.o verifier.log` 构建 `ProgramCFG`，并在 section/pc 布局匹配时把 verifier states attach 到 `InsnSite`。
- [x] JSON metadata 暴露 CFG-backed facts，比如 section、instruction count、block count、attached verifier-state site count。
- [x] 保持 `bpfix verifier.log` log-only 路径独立可用。
- [x] 保持普通 runtime 路径不依赖 `case.yaml` labels。
- [x] 用 benchmark corpus 做 smoke verification，确认所有 replay log 至少能输出诊断。
- [x] 找 subagent 做 review，根据问题修复。

## 后续

- [ ] 做 BTF line-info source correlation。
- [ ] 让 object section 匹配使用 libbpf load log / BTF.ext / program name，而不是只做 pc-layout best effort。
- [ ] 把 proof lifecycle 从 pointer provenance 扩展到 scalar range、null refinement、stack init、reference lifecycle。

## 边界

- `bpfanalysis`：facts and primitives only。
- `bpfix`：diagnostic product layer。
- `case.yaml`：evaluation oracle only。
