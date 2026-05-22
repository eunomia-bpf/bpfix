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
(`stackoverflow-53136145`). The source parses either IPv4 or IPv6, derives a
UDP header pointer on each branch, checks the UDP header against `data_end`, and
then reads the destination port:

```c
if (ethertype == ETH_P_IP) {
    ipv4_hdr = (void *)eth + ETH_HLEN;
    if ((void *)(ipv4_hdr + 1) > data_end)
        return 1;
} else if (ethertype == ETH_P_IPV6) {
    ipv6_hdr = (void *)eth + ETH_HLEN;
    if ((void *)(ipv6_hdr + 1) > data_end)
        return 1;
} else {
    return 2;
}

if (ipv4_hdr)
    udph = (void *)ipv4_hdr + sizeof(*ipv4_hdr);
else
    udph = (void *)ipv6_hdr + sizeof(*ipv6_hdr);

if (udph + sizeof(struct udphdr) > data_end)
    return 1;

dst_port = __constant_ntohs(((struct udphdr *)udph)->dest);
```

That source shape is normal BPF C: the developer made the packet proof explicit.
The failure is in the verifier-visible proof after lowering. One replay path
reaches the shared `udph->dest` load with `r5` as a scalar instead of a packet
pointer:

```text
from 31 to 34: ... R5_w=40 ...
; if (udph + sizeof(struct udphdr) > data_end) @ prog.c:267
34: (bf) r3 = r5                      ; R3_w=40 R5_w=40
35: (07) r3 += 8                      ; R3=48
36: (2d) if r3 > r2 goto pc+4         ; R2=pkt_end() R3=48
; dst_port = __constant_ntohs(((struct udphdr *)udph)->dest); @ prog.c:270
37: (69) r2 = *(u16 *)(r5 +2)
R5 invalid mem access 'scalar'
```

The raw log says where the verifier stopped, but not the source-level proof
story. BPFix turns the trace into a Rust-style multi-span diagnostic:

```text
error[BPFIX-E006]: pointer type proof is missing
  = class: lowering_artifact
  --> prog.c:270
   |
263 | if (ipv4_hdr)
    | ------------- proof can be lost when branch-specific pointers are merged
267 | if (udph + sizeof(struct udphdr) > data_end)
    | -------------------------------------------- proof established by a verifier-visible bounds check
270 | dst_port = __constant_ntohs(((struct udphdr *)udph)->dest);
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ rejected here: verifier sees a scalar where a pointer is required
   |
   = verifier[229]: R5 invalid mem access 'scalar'
   = note: nearest BPF instruction pc 37
   = note: parsed 60 verifier state snapshots
   = required proof: preserve a verifier-recognized pointer type at the operation that requires a pointer
help: Keep branch-specific pointer derivations in separate verifier-visible branches, or rederive the pointer from a checked base immediately before dereferencing it.
help: Avoid integer casts or arithmetic that turn the pointer into a scalar before the access.
help: Recompute the pointer from a verifier-tracked base after scalar manipulation.
```

This is the kind of failure that motivates the project: the program is not
missing a generic "add a bounds check" hint. The useful answer is the proof
lifecycle: where a verifier-recognized pointer proof exists, where branch-local
provenance can be merged away, and where the rejected instruction finally needs
that proof.

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

Pass a full libbpf or build log directly; BPFix extracts the verifier region
when the log contains surrounding build output:

```bash
cargo run -p bpfix -- build-or-load.log
```

Optionally pass the BPF object. BPFix reads BPF instruction sections, builds a
`ProgramCFG`, correlates verifier states to CFG sites when the log PC layout
matches the object section, and reports CFG metadata in JSON. BTF-backed source
correlation will build on the same CLI shape:

```bash
cargo run -p bpfix -- --object xdp.o verifier.log
```

Get JSON for CI or editor integration:

```bash
cargo run -p bpfix -- verifier.log --format json
```

Run it on a benchmark YAML record when evaluating BPFix against the bundled
corpus. The CLI only extracts the verifier log and case ID from YAML; labels are
kept as evaluation oracles, not runtime inputs:

```bash
cargo run -p bpfix -- bpfix-bench/raw/so/stackoverflow-60053570.yaml
```

## Best Workflow

The best user experience is to keep your current BPF workflow and let BPFix
explain the verifier log it already produces:

```bash
make load 2>&1 | tee verifier.log
bpfix verifier.log
```

or:

```bash
sudo bpftool prog load xdp.o /sys/fs/bpf/xdp 2> verifier.log
bpfix --object xdp.o verifier.log
```

BPFix does not need `case.yaml` for normal use. YAML records are for the bundled
benchmark and later accuracy evaluation.

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

The current user-facing pipeline is log-first: `bpfix` parses verifier state
snapshots, instantiates the required verifier proof from the terminal error
and verifier state, extracts proof lifecycle events, and maps them back to
source comments when the log contains BTF/source annotations. Packet bounds,
scalar range, nullable pointer, stack readability, reference lifecycle, helper
capability, and pointer-provenance failures now produce parameterized proof
requirements instead of only terminal-error categories. The CLI accepts an
optional `--object prog.o` today, builds `ProgramCFG` summaries, and correlates
verifier-state PCs with CFG sites when the object section layout matches the
loaded verifier program. Full BTF source correlation is the next analysis
layer, not a runtime requirement for the basic CLI.

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
