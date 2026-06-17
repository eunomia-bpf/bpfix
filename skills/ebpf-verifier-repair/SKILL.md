---
name: ebpf-verifier-repair
description: End-to-end workflow for diagnosing and repairing eBPF verifier rejections in C, Rust/Aya, libbpf, libbpf-rs, BCC, bpftool, and CI logs using BPFix. Use when Codex is asked to fix, explain, or patch verifier errors, verifier logs, BPFIX diagnostics, packet bounds, nullable pointer, stack initialization, reference lifetime, scalar range, pointer provenance, compiler lowering artifact, helper/kfunc/dynptr/iterator, RCU/IRQ/lock, environment capability, or verifier budget failures.
---

# eBPF Verifier Repair

## Overview

Repair verifier failures as missing proof obligations, not as string-matched
terminal errors. Use `bpfix` as the evidence engine, then make the smallest
verifier-visible source change that preserves program semantics and proves the
required safety fact to the kernel verifier.

Do not split work into one skill per verifier error family. `BPFIX-E*`,
`failure_class`, and `next_action` values are routing signals inside this
workflow; the reusable user job is "repair this verifier rejection."

## Resource Routing

- Read `references/log-collection.md` when the user did not provide a full
  verbose verifier log, the log is incomplete, or the framework/loader command
  is unclear.
- Read `references/diagnostic-routing.md` before turning a BPFix JSON
  diagnostic into a repair plan, especially when `failure_class`,
  `help_safety`, or `diagnostic_kind` changes what is safe to edit.
- Read `references/repair-patterns.md` before editing source, selecting a
  verifier-visible rewrite, or reviewing a proposed patch.
- Run `scripts/run-bpfix-diagnostic.sh` when a log file is available and a
  repeatable JSON/text diagnostic artifact would make the repair loop clearer.

## Repair Workflow

1. Establish the failing load path.
   Identify the loader command, framework, BPF source file, compiled object if
   available, kernel/program type, and the exact command that produced the
   rejection. Preserve the full verbose verifier/build/load log; the final
   `Permission denied` or `invalid argument` line is not enough.

2. Run BPFix before editing.
   Prefer JSON plus text output:

   ```bash
   bpfix --format both verifier.log
   bpfix --format json --fail-on-unsupported verifier.log > bpfix-diagnostic.json
   bpfix --object prog.o --format json verifier.log
   ```

   If this skill is checked out with the BPFix repo, the helper script can
   produce both artifacts:

   ```bash
   skills/ebpf-verifier-repair/scripts/run-bpfix-diagnostic.sh --out .bpfix-agent verifier.log
   skills/ebpf-verifier-repair/scripts/run-bpfix-diagnostic.sh --object prog.o verifier.log
   ```

3. Route by proof evidence, not by prose alone.
   Inspect `diagnostic_kind`, `failure_class`, `help_safety`, `next_action`,
   `required_proof`, `source_span`, `related_spans`, and `evidence`. If BPFix
   reports unsupported input, fix log collection first. If it reports an
   environment/configuration failure, confirm kernel/program-type/helper/BTF
   availability before editing source.

4. Form a proof-obligation hypothesis.
   State the fact the verifier could not prove at the rejected instruction:
   packet bounds, non-nullness, initialized stack bytes, live reference release,
   scalar range, pointer provenance/type, alignment, helper/kfunc contract,
   dynptr protocol, execution context, or complexity bound. Name where the
   proof is established, lost, or missing.

5. Edit the source minimally and verifier-visibly.
   Prefer rewrites that keep the checked value and the used value in the same
   verifier-visible path. Revalidate after helpers that invalidate pointers.
   Re-derive pointers from checked bases near use when compiler lowering or
   branch merging hides provenance. Do not add unrelated checks or broad casts
   that change semantics without proving the required fact.

6. Validate the repair.
   Rebuild the BPF object, rerun the original load/replay command, and rerun
   `bpfix` on any new verifier log. A successful repair means the original
   rejection no longer appears and no new verifier rejection replaces it. When
   privileged loading is not available, run compile/tests and explain the
   remaining verification gap.

7. Report the result in proof terms.
   Summarize the changed proof, the files touched, the validation command and
   result, and any kernel/environment assumption that remains.

## Source Editing Rules

- Preserve BPF program semantics first; verifier acceptance is not sufficient
  if the runtime behavior changes.
- Keep fixes local to the rejected proof path unless evidence shows a shared
  helper, macro, or abstraction owns the missing proof.
- Treat `lowering_artifact` as a bytecode-shape problem: duplicate small
  branches, keep pointer values typed, or rederive from a tracked base instead
  of only adding a source-level check that may lower away.
- Treat `verifier_false_positive` and `help_safety: triage_only` as cautious
  triage: simplify the relation or test another kernel before claiming a source
  bug.
- Prefer framework-native idioms: libbpf C helpers/macros for C programs, Aya
  APIs for Rust loaders/programs, and BCC conventions for Python/C snippets.
- Do not hide verifier-sensitive code behind opaque helper calls unless the
  verifier can inline or otherwise see the proof.

## Completion Criteria

Finish only after one of these is true: the verifier load/replay passes; the
project's available test path passes and the missing privileged verifier step is
explicitly documented; or the evidence shows the issue is environment-only and
the correct non-source change is identified.
