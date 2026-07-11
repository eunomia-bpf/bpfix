---
name: ebpf-verifier-repair
description: End-to-end workflow for diagnosing and repairing eBPF verifier rejections in C, Rust/Aya, libbpf, libbpf-rs, BCC, bpftool, and CI logs from raw verbose verifier logs, BPFix diagnostics, or source/test failures. Use when Codex is asked to fix, explain, or patch verifier errors, verifier logs, BPFIX diagnostics, packet bounds, nullable pointer, stack initialization, reference lifetime, scalar range, pointer provenance, compiler lowering artifact, helper/kfunc/dynptr/iterator, RCU/IRQ/lock, environment capability, or verifier budget failures.
license: MIT
---

# eBPF Verifier Repair

## Overview

Repair verifier failures as missing proof obligations, not as string-matched
terminal errors. A full verbose verifier log plus source is sufficient evidence
to start; use `bpfix` only when it is available and helpful. Make the smallest
verifier-visible source change that preserves program semantics and proves the
required safety fact to the kernel verifier.

Do not split work into one skill per verifier error family. `BPFIX-E*`,
`failure_class`, and `next_action` values are routing signals inside this
workflow; the reusable user job is "repair this verifier rejection."

## Resource Routing

- Read `references/log-collection.md` when the user did not provide a full
  verbose verifier log, the log is incomplete, or the framework/loader command
  is unclear.
- Read `references/raw-log-triage.md` whenever repairing from a raw verifier
  log. Use its rejected-instruction and proof-lifecycle procedure before
  selecting a source rewrite.
- Read `references/diagnostic-routing.md` only when a BPFix diagnostic is
  provided or generated. Do not block raw-log repair on this file.
- Read `references/repair-patterns.md` before editing source, selecting a
  verifier-visible rewrite, or reviewing a proposed patch.
- Read `references/semantic-preservation.md` before editing a nontrivial
  program, especially when it updates maps, emits events, has fallback policy,
  or uses multiple acquired resources.
- Read `references/failure-directed-retry.md` after any candidate fails to
  compile, load, or pass the semantic oracle. Route the next edit by the failure
  stage instead of starting a new speculative repair.
- Run `scripts/run-bpfix-diagnostic.sh` only when BPFix is available and a
  repeatable plain-text diagnostic artifact would make the repair loop clearer.
- Run `scripts/extract_verifier_failure.py verifier.log` when a raw log is too
  large for the working context. Keep the original log and inspect omitted PCs
  when the initial slice does not reveal proof origin or loss.

## Repair Workflow

1. Establish the failing load path.
   Identify the loader command, framework, BPF source file, compiled object if
   available, kernel/program type, and the exact command that produced the
   rejection. Preserve the full verbose verifier/build/load log; the final
   `Permission denied` or `invalid argument` line is not enough.

2. Choose the evidence path.
   If only source and a raw verbose verifier log are available, work directly
   from them. Find the rejected instruction, terminal verifier message,
   register state, helper call, source annotation, and the earlier branch or
   check that should have established the missing proof. Do not wait for BPFix.

   If BPFix is available and the user did not ask for a raw-log-only repair, it
   can add proof-aware plain-text evidence:

   ```bash
   bpfix verifier.log
   bpfix --fail-on-unsupported verifier.log > bpfix-diagnostic.txt
   bpfix --object prog.o verifier.log
   ```

   If this skill is checked out with the BPFix repo, the helper script can
   produce a repeatable plain-text artifact:

   ```bash
   skills/ebpf-verifier-repair/scripts/run-bpfix-diagnostic.sh --out .bpfix-agent verifier.log
   skills/ebpf-verifier-repair/scripts/run-bpfix-diagnostic.sh --object prog.o verifier.log
   ```

3. Route by proof evidence, not by prose alone.
   Inspect the diagnostic class, safety/confidence labels, next action,
   required proof, source spans, and verifier evidence when a diagnostic
   exists. With raw logs, infer the same facts manually from the
   rejected PC, register classes/ranges, helper arguments, and source lines. If
   the log is incomplete, fix log collection first. If the evidence points to
   environment/configuration failure, confirm kernel/program-type/helper/BTF
   availability before editing source.

4. Freeze the semantic contract.
   List the observable behavior that the repair must preserve: program section
   and return actions, packet or context fields consumed, map keys and values,
   state mutations, event contents, helper calls, resource lifecycle, fallback
   behavior, and meaningful branch outcomes. Read the project's tests and
   loader when available. Distinguish a safety guard from a policy decision;
   do not turn a missing proof into a new policy.

5. Form a proof-obligation hypothesis.
   State the fact the verifier could not prove at the rejected instruction:
   packet bounds, non-nullness, initialized stack bytes, live reference release,
   scalar range, pointer provenance/type, alignment, helper/kfunc contract,
   dynptr protocol, execution context, or complexity bound. Name where the
   proof is established, lost, or missing.

6. Edit the source minimally and verifier-visibly.
   Prefer rewrites that keep the checked value and the used value in the same
   verifier-visible path. Revalidate after helpers that invalidate pointers.
   Re-derive pointers from checked bases near use when compiler lowering or
   branch merging hides provenance. Do not add unrelated checks or broad casts
   that change semantics without proving the required fact.

7. Validate the repair.
   Rebuild the BPF object, rerun the original load/replay command, and rerun
   `bpfix` on any new verifier log only if BPFix was part of the evidence path.
   A successful repair means the original rejection no longer appears, no new
   verifier rejection replaces it, and the project's semantic oracle still
   passes. If a stage fails, follow `references/failure-directed-retry.md` and
   make the next edit answer that evidence. When privileged loading is not
   available, run compile/tests and explain the remaining verification gap.

8. Report the result in proof terms.
   Summarize the changed proof, the files touched, the validation command and
   result, and any kernel/environment assumption that remains.

## Source Editing Rules

- For full-source repairs, return a complete compilable source file. Preserve
  includes, map definitions, helper prototypes, `SEC()` sections, license,
  constants, function names, and loader-visible symbols unless the evidence
  specifically requires changing them.
- Preserve BPF program semantics first; verifier acceptance is not sufficient
  if the runtime behavior changes.
- Keep fixes local to the rejected proof path unless evidence shows a shared
  helper, macro, or abstraction owns the missing proof.
- Do not delete functionality, weaken filters, change return values, remove map
  operations, or replace helper calls merely to make the verifier accept the
  program.
- When a candidate fails to compile or is malformed, fix syntax, braces,
  includes, macros, and complete-source formatting before changing verifier
  logic.
- When a candidate loads but fails the project's oracle, treat that as a real
  semantic regression. Reopen the proof hypothesis and preserve the original
  dataflow, side effects, and observable outputs.
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
