# BPFix Integration Examples

BPFix is easiest to use as a log filter:

```text
existing eBPF workflow emits verifier/build log -> bpfix reads the log -> plain text diagnostic
```

The bpftool quick start captures the verifier log, then asks BPFix to explain
that saved log:

```bash
sudo bpftool -d prog load examples/bpftool/motivating-example.bpf.o /sys/fs/bpf/bpfix-demo 2>&1 | tee verifier.log
bpfix verifier.log
```

## Directory Map

| path | audience | what it shows |
| --- | --- | --- |
| `bpftool/` | users loading `.o` files directly | `bpftool -d` capture plus log-first diagnosis |
| `make/` | existing C/Rust/eBPF projects | Makefile targets that preserve the original load command |
| `libbpf-c/` | C loaders and skeleton users | libbpf verifier-log buffer setup and post-failure diagnosis |
| `libbpf-rs/` | Rust loaders using libbpf-rs | stderr/log capture around an existing loader binary |
| `aya/` | Aya users | Rust loader snippet and logging wrapper |
| `bcc/` | Python/BCC users | Python error capture plus optional `bpfix` subprocess call |
| `ci/` | CI maintainers | GitHub Actions artifact flow for `verifier.log` and BPFix text |
| `editor/` | editor and agent integrations | plain-text diagnostic handoff |

The bpftool quick start uses the committed `bpftool/motivating-example.bpf.o`
object from the root README motivating example. Other examples intentionally
keep placeholders such as `xdp.o`, `./loader`, and `cargo run --bin loader`.
Replace them with the command that already fails in your project. BPFix should
sit beside that command; it should not force you to rewrite the loader just to
get a useful diagnostic.

## Support Levels

| capability | status | user command |
| --- | --- | --- |
| File or stdin verifier/build/load log | stable default | `bpfix verifier.log` |
| Plain text diagnostic | stable default | `bpfix verifier.log` |
| Existing bpftool/libbpf/Aya/BCC output | stable when the log includes the verifier region | capture stderr/stdout, then run `bpfix` |
| Object metadata | feature-gated | build with `--features object-analysis`, then pass `--object prog.o` |
| Docker or command execution | not a default example path | use only if a future explicit option is implemented |

The default examples avoid feature-gated options. Set
`BPFIX_OBJECT_ANALYSIS=1` only after installing BPFix with
`--features object-analysis`.

Run the lightweight consistency check after editing examples:

```bash
./examples/check-examples.sh
```
