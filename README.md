# BPFix

**BPFix makes eBPF verifier errors feel closer to Rust compiler errors.**

The Linux eBPF verifier is powerful, but its failure logs are hard to read. A
developer usually sees a long `bpftool`, libbpf, Aya, or BCC log and then has to
guess which safety proof the verifier could not establish.

BPFix is a userspace diagnostic layer for that problem. It reads verifier logs
from your existing workflow and turns them into:

- a stable `BPFIX-*` error ID
- a short explanation of what the verifier could not prove
- the nearest instruction or source location when the log contains one
- practical repair hints
- JSON output for editors, CI, and other tools

BPFix does not replace Aya, libbpf-rs, `bpftool`, or the kernel verifier. It
sits next to them and explains verifier failures after they happen.

## Motivating Example

Here is a real verifier failure from `bpfix-bench`
(`stackoverflow-70750259`). The source has packet bounds checks, but the value
used to advance the packet cursor is assembled from packet bytes, byte-swapped,
stored to the stack, and reloaded as a signed scalar:

```c
if (data_end < data + sizeof(struct extension))
    return XDP_DROP;

struct extension *ext = (void *)data;
volatile int ext_len = __bpf_htons(ext->len);

if (ext_len < 0)
    return XDP_DROP;

data += ext_len;
```

The raw verifier log is technically accurate, but it is hard to turn into a
repair:

```text
; volatile int ext_len = __bpf_htons(ext->len); @ prog.c:274
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
24: (63) *(u32 *)(r10 -4) = r0

; data += ext_len; @ prog.c:280
30: (61) r0 = *(u32 *)(r10 -4)
31: (67) r0 <<= 32
32: (c7) r0 s>>= 32
33: (0f) r5 += r0
value -2147483648 makes pkt pointer be out of bounds
```

The final line points at `data += ext_len`, but the useful diagnostic is the
missing proof: the verifier needs a bounded, non-negative scalar at the packet
pointer addition. BPFix turns that into a Rust-style diagnostic:

```text
BPFIX-E005 [lowering_artifact]
message: scalar range proof is missing: value -2147483648 makes pkt pointer be out of bounds
missing obligation: bound the scalar value tightly enough for the verifier to prove the memory access range
span: prog.c:280 pc=33
evidence:
  - terminal_verifier_error at log line 121: value -2147483648 makes pkt pointer be out of bounds
  - instruction_pc at log line 121: nearest verifier instruction pc 33
  - verifier_trace: parsed 30 per-instruction verifier state snapshots
candidate repairs:
  - Clamp the index or length with explicit upper and lower bounds.
  - Keep the bounded scalar in the same SSA value used for pointer arithmetic or helper length.
```

This is the kind of failure that motivates the project: the program is not
missing a generic "add a bounds check" hint. The developer needs to understand
which verifier proof was lost and where to make that proof visible again.

## Quick Start

Build the workspace:

```bash
git submodule update --init --recursive
cargo build --workspace
```

Run BPFix on a verifier log:

```bash
cargo run -p bpfix -- verifier.log
```

Pipe a failing load command into BPFix:

```bash
sudo bpftool prog load xdp.o /sys/fs/bpf/xdp 2>&1 | cargo run -p bpfix --
```

Run it on a benchmark YAML record:

```bash
cargo run -p bpfix -- bpfix-bench/raw/so/stackoverflow-60053570.yaml
```

Get JSON for CI or editor integration:

```bash
cargo run -p bpfix -- verifier.log --format json
```

## Best Workflow

The best user experience is to keep your current BPF workflow and let BPFix
explain failures.

Today, BPFix works as a log post-processor:

```bash
bpftool ... 2>&1 | bpfix
cargo run -p bpfix -- verifier.log
```

The intended next CLI shape is:

```bash
bpfix check -- <your existing command>
```

For example:

```bash
bpfix check -- cargo test
bpfix check -- make load
bpfix check -- sudo bpftool prog load xdp.o /sys/fs/bpf/xdp
```

That mode should run the command normally, capture verifier output, and print a
Rust-style diagnostic only when the load fails.

## Project Status

This repository is currently a Rust rewrite of the original Python prototype.
The active code is the Rust workspace:

```text
crates/
  bpfix/        command-line diagnostic tool
  bpfanalysis/  verifier-log and BPF bytecode analysis primitives
```

The old Python implementation is archived under `docs/bpfix-py/` for reference.
It is not the active development surface.

The `bpfanalysis` crate imports analysis code from the `bpfopt` project and
uses `libbpf-sys` for BPF instruction and program-type constants. The libbpf
source is tracked as a submodule in `vendor/libbpf`.

## What BPFix Handles

Current diagnostics focus on common verifier failures:

- packet bounds checks
- nullable map value pointers
- uninitialized stack reads
- reference lifetime leaks
- scalar range and variable-offset problems
- pointer type/provenance loss
- verifier complexity and loop limits
- missing kernel/helper/program-type support
- dynptr lifetime and bounds issues

## Non-Goals

BPFix is not:

- a kernel patch
- a verifier replacement
- an automatic source-code repair tool
- a semantic correctness checker for accepted BPF programs

It explains why the verifier rejected a program and what proof the developer
probably needs to make explicit.

## Development

Run tests:

```bash
cargo test --workspace
```

Check the workspace:

```bash
cargo check --workspace
```

Format code:

```bash
cargo fmt --all
```

Run a smoke test:

```bash
cargo run -p bpfix -- bpfix-bench/raw/so/stackoverflow-60053570.yaml --format both
```

## Repository Layout

```text
bpfix-bench/       replayable verifier-failure corpus and raw examples
crates/bpfanalysis Rust analysis library
crates/bpfix       user-facing CLI
docs/evaluation/   benchmark and metric notes
docs/bpfix-py/     archived Python prototype
vendor/libbpf/     libbpf submodule
```
