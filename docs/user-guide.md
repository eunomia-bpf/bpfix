# BPFix User Guide

BPFix explains eBPF verifier rejections from logs you already have. It does not
run your loader, mutate your program, or require benchmark metadata.

## Install

From this repository:

```bash
cargo install --path crates/bpfix
```

Or run without installing:

```bash
cargo run -p bpfix -- verifier.log
```

## Get A Verifier Log

Use your normal workflow and keep the full load output:

```bash
sudo bpftool -d prog load xdp.o /sys/fs/bpf/xdp 2>&1 | tee verifier.log
bpfix verifier.log
```

For libbpf, pass the full stderr/build/load log:

```bash
make load 2>&1 | tee load.log
bpfix load.log
```

Stdin works the same way:

```bash
sudo bpftool -d prog load xdp.o /sys/fs/bpf/xdp 2>&1 | bpfix
```

The positional argument and stdin are always interpreted as verifier/build/load
log text.

BPFix strips common wrappers before looking for the verifier region, including
ANSI color escapes, ISO-8601 timestamp prefixes, and GitHub Actions group
markers. That means a copied CI artifact usually works without hand-editing.

BPFix does not execute the loader command for you. Docker or replay
environments, if added later, should be selected by explicit options such as
`--docker`; they do not change what the positional argument or stdin means.

## Optional Object Metadata

`--object` is optional and experimental. It requires a build with the
`object-analysis` feature:

```bash
cargo install --path crates/bpfix --features object-analysis
bpfix --object xdp.o verifier.log
```

Use it when you want JSON metadata about BPF object sections and verifier-state
attachment. Do not rely on it as complete BTF-backed source correlation yet.
If you pass `--object` to a default build, BPFix still emits the log diagnostic
and reports that object analysis is disabled.

## Output Modes

Human-readable text is the default:

```bash
bpfix verifier.log
```

JSON is for CI, editors, and agents:

```bash
bpfix --format json verifier.log
```

Both outputs:

```bash
bpfix --format both verifier.log
```

## Reading A Diagnostic

Example:

```text
error[BPFIX-E006]: verifier-visible compiler lowering hides the required proof
  = class: lowering_artifact
  = confidence: medium
  = diagnostic: supported, help: repair_hint, span: exact_pc
  --> prog.c:270
   |
267 | if (udph + sizeof(struct udphdr) > data_end)
    | -------------------------------------------- verifier state changes from pkt to scalar before the rejected access
270 | dst_port = __constant_ntohs(((struct udphdr *)udph)->dest);
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ rejected here: verifier sees a scalar where a pointer is required
   |
   = note[lowering]: compiler-lowered control flow hides an established packet-pointer proof
```

Fields:

- `error_id`: stable family identifier for tooling and docs.
- `class`: broad action class, such as `source_bug`, `lowering_artifact`,
  `verifier_false_positive`, `environment_or_configuration`,
  `verifier_limit`, or `input_error`.
- `confidence`: confidence in the diagnostic family.
- `diagnostic`: `supported`, `unsupported_input`, or
  `unsupported_verifier_message`.
- `help`: whether the help is a repair hint or triage-only guidance.
- `span`: how strong the source/PC location evidence is.
- `note[...]`: extra evidence for a runtime classification, such as a
  compiler-lowering artifact or verifier precision boundary.

## Common Actions

For `source_bug`, inspect the primary span and required proof. BPFix is telling
you which verifier-visible fact was missing, such as packet bounds, scalar
range, pointer type, stack initialization, or reference lifetime.

For `lowering_artifact`, the source may already contain a meaningful proof, but
the verifier-visible bytecode lost it through branch merging, pointer
materialization, stack alignment, or another compiler-lowered shape. Prefer a
verifier-visible rewrite over simply adding an unrelated check.

For `verifier_false_positive`, BPFix found evidence of a verifier precision
boundary. Treat the help as triage guidance: simplify the relation, add an
explicit clamp, or test on a kernel with the relevant verifier fix before
concluding the source is semantically unsafe.

For `environment_or_configuration`, check program type, attach type, helper or
kfunc availability, BTF, kernel version, privileges, and JIT/support settings
before changing source code.

For `verifier_limit`, reduce state growth: add static loop bounds, simplify
branching, split large programs, or reduce combined stack use.

For `input_error`, collect the full verbose verifier log. A final loader error
alone is usually not enough.

## Supported Families

Current log-first diagnostics cover:

- packet bounds
- nullable pointer checks
- stack initialization
- reference lifetime
- scalar range
- pointer provenance and pointer type
- verifier-visible compiler lowering artifacts
- verifier precision boundaries and likely false positives
- alignment
- helper/subprogram argument contracts
- context and kernel-struct field access
- dynptr protocol issues
- kfunc trusted-pointer and reference contracts
- iterator lifecycle
- lock, RCU, and IRQ discipline
- kernel/program-type capability boundaries
- verifier complexity and loop/stack limits

Some families have exact PC/source spans; others are terminal-line or nearby
source-context diagnostics. JSON consumers should read `span_confidence` before
automatically highlighting source.

## CI Pattern

One simple CI pattern is to preserve the loader log as an artifact and emit JSON:

```bash
make load 2>&1 | tee verifier.log
bpfix --format json verifier.log > bpfix-diagnostic.json
```

Do not fail CI only because BPFix emits `input_error`; treat that as a log
collection problem and upload the full loader output.
