# Workshop Paper Plan

This document defines the near-term workshop submission story for BPFix.
It supersedes historical synthesis-oriented notes in `docs/tmp/`.

## Thesis

BPFix is a userspace diagnostic layer for eBPF verifier failures. The core
claim is that verbose verifier logs already contain a proof-attempt trace:
per-instruction abstract register state, scalar bounds, pointer provenance,
source comments, and backtracking notes. BPFix parses that trace and turns it
into Rust-style diagnostics that explain:

- what verifier proof was required
- where that proof was visible, if the trace shows it
- where the proof was lost or became insufficient, if the trace shows it
- where the verifier rejected the program

## Submission Shape

The workshop paper should be a focused systems-tool paper, not an automatic
patch-synthesis paper.

Working title:

```text
BPFix: Rust-Style Diagnostics for eBPF Verifier Failures
```

Primary audience:

- BPF and kernel-tooling developers
- verifier maintainers interested in better diagnostics
- developers building CI, editor, and agent workflows around eBPF

Best-fit venue type:

- BPF/Linux developer workshop or track proposal
- systems workshop with emphasis on tools, diagnostics, and kernel developer
  productivity

## Claims To Make

The paper can safely claim:

- BPFix works entirely in userspace and requires no kernel patches.
- BPFix consumes logs from existing workflows: `bpftool`, libbpf, Aya,
  libbpf-rs, BCC, or CI build logs.
- BPFix reconstructs required verifier proofs for common failure families.
- BPFix emits multi-span diagnostics with stable error IDs and structured JSON.
- Optional object analysis can attach verifier states to decoded BPF CFG sites.

The paper should not claim:

- automatic source patch generation
- verifier-pass patch-synthesis success
- semantic correctness of accepted patched programs
- replacement of the kernel verifier
- complete coverage of all verifier messages or all kernel versions

## Evaluation Plan

Use `bpfix-bench/manifest.yaml` as the case registry. Report:

- log-only diagnostic success over all admitted cases
- required-proof coverage by proof family
- source or bytecode localization coverage
- object-CFG attachment success when objects are available
- failure modes for unknown verifier messages and object-analysis errors
- latency for log-only and object-enriched modes

Baselines:

- terminal verifier line only
- Pretty Verifier or equivalent message-level tool when reproducible
- optional LLM/log baseline only as secondary evidence, not as the headline

## Main Example

Use a proof-lifecycle example where the final verifier line is only a symptom:

- proof established by a visible bounds/null/provenance check
- proof lost through lowering, branch merge, spill/reload, or scalar widening
- rejected at a later access or helper call

The Stack Overflow branch-merge provenance case
`stackoverflow-53136145` is currently a strong candidate because the diagnostic
shows established, lost, and rejected spans in one compact example.

## Open Questions Before Submission

- Finish the current Rust evaluation over all admitted benchmark logs.
- Decide whether the workshop version reports object-CFG results or leaves full
  BTF-backed source recovery as future work.
- Freeze the JSON fields used by the paper artifact.
- Pick one primary example and two short secondary examples.
