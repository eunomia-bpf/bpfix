# BPFix Integration Examples

BPFix is easiest to use as a log filter:

```text
existing eBPF workflow emits verifier/build log -> bpfix reads the log -> plain text diagnostic
```

The default CLI accepts either a file or stdin:

```bash
bpfix verifier.log
make load 2>&1 | bpfix
```

Use JSON only when another tool consumes the result:

```bash
bpfix --format json verifier.log
```

## Directory Map

| path | audience | what it shows |
| --- | --- | --- |
| `bpftool/` | users loading `.o` files directly | `bpftool -d` capture plus `bpfix --object` |
| `make/` | existing C/Rust/eBPF projects | Makefile targets that preserve the original load command |
| `libbpf-c/` | C loaders and skeleton users | libbpf verifier-log buffer setup and post-failure diagnosis |
| `libbpf-rs/` | Rust loaders using libbpf-rs | stderr/log capture around an existing loader binary |
| `aya/` | Aya users | Rust loader snippet and logging wrapper |
| `bcc/` | Python/BCC users | Python error capture plus optional `bpfix` subprocess call |
| `ci/` | CI maintainers | GitHub Actions artifact flow for `verifier.log` and JSON |
| `editor/` | editor and agent integrations | stable JSON diagnostic handoff |

The examples intentionally keep placeholders such as `xdp.o`, `./loader`, and
`cargo run --bin loader`. Replace them with the command that already fails in
your project. BPFix should sit beside that command; it should not force you to
rewrite the loader just to get a useful diagnostic.
