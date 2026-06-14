# Analysis Integration Todo

This is the working checklist for turning BPFix from a verifier-log formatter
into a reusable proof-lifecycle diagnostic engine.

## Community Target

BPFix should be useful without changing a developer's BPF workflow. A user
should be able to pipe a failed `bpftool`, libbpf-rs, Aya, or BCC load log into
`bpfix` and get a Rust-style diagnostic that says:

- what verifier proof was required
- where that proof was established, if visible in the trace
- where the proof was lost or became verifier-invisible, if visible
- where the verifier finally rejected the program
- what source rewrite is likely to make the proof visible again

The innovative part is not prettier formatting. The useful part is recovering a
source-level proof lifecycle from the verifier's per-instruction abstract-state
trace.

## Done

- [x] Keep `bpfix` as a userspace log post-processor for the first public path.
- [x] Import the `bpfopt` analysis code into `crates/bpfanalysis`.
- [x] Parse verifier state snapshots from log-level-2 verifier output.
- [x] Expose neutral verifier-log facts from `bpfanalysis` and keep
      user-facing diagnostic rules in `bpfix`.
- [x] Instantiate first-pass required proofs from terminal verifier errors and
      parsed verifier state, including concrete registers, packet/map ranges,
      scalar ranges, nullable values, helper names, and reference IDs where
      visible.
- [x] Emit proof lifecycle events: `proof_established`, `proof_lost`, and
      `rejected`.
- [x] Map proof events to source spans when verifier logs include
      `; source @ file:line` annotations.
- [x] Refactor `crates/bpfix` so multi-span diagnostics come from the
      `bpfix::diagnostic` product layer, not ad hoc CLI-local source scanning.
- [x] Make the runtime log path independent from `case.yaml`; benchmark YAML is
      evaluation-only and is not parsed by the public CLI.
- [x] Extract the verifier region from full libbpf/build logs before analysis.
- [x] Accept an optional `--object prog.o`, read BPF instruction sections, build
      `ProgramCFG` summaries, correlate verifier states by PC when the loaded
      verifier layout matches the object section, and expose CFG metadata in
      diagnostics.
- [x] Cover the branch-merge provenance example
      `stackoverflow-53136145` in analysis and CLI tests.
- [x] Add focused lifecycle regression tests for packet bounds, scalar range,
      nullable pointer, stack readability, reference lifecycle, and helper
      capability diagnostics.
- [x] Keep runtime diagnostics independent from YAML labels and case IDs; JSON
      `metadata.case_id` is populated only by an explicit `--case-id`.

## Next

- [ ] Use `--object prog.o` for real BTF source correlation when source comments
      are sparse or missing.
- [ ] Move source correlation from log comments to BTF line records when an
      object is available.
- [ ] Replace the current source-comment heuristics for scalar/null/reference
      proof loss with CFG-aware value-lineage and path analysis.
- [ ] Track register lineage across copies, spills, reloads, and branch joins so
      proof events follow the value that matters instead of only one register
      number.
- [ ] Rank user-facing help text from the detected proof lifecycle rather than only the
      terminal error class.
- [ ] Add golden tests for at least one representative case per required-proof
      class.
- [ ] Keep JSON stable enough for editors and CI integrations.

## Current Limitations

- The first public API is log-driven. It does not require source code, YAML, or
  an object file.
- `--object` builds CFG summaries and records verifier-state/CFG correlation
  status, but BTF-backed source correlation is still future work.
- Source spans require verifier logs with source comments until object-backed
  correlation is implemented.
- The proof-lost engine is strongest today for pointer provenance and branch
  merge failures. Other required-proof classes still need deeper value-lineage
  tracking.
- Benchmark `case.yaml` labels are evaluation oracles. Runtime diagnostics read
  only log text; use `--case-id` when a caller wants bookkeeping metadata.
