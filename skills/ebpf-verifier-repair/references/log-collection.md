# Log Collection

BPFix needs the full verbose verifier region, including instruction states and
source annotations when available. A final loader errno line alone is usually
not enough.

## Collection Rules

- Keep stdout and stderr together with `2>&1 | tee verifier.log`.
- Prefer verbose loader modes: `bpftool -d`, libbpf debug prints, framework
  debug logs, or CI artifacts that preserve the full build/load output.
- Do not hand-trim the middle of the verifier trace. If the log is huge, keep
  the complete artifact on disk and pass the path to `bpfix`.
- Preserve the compiled `.o` when possible. Object analysis is optional but can
  improve PC/source correlation when BPFix is built with `object-analysis`.
- Record kernel version, program type, attach type, loader command, and whether
  CAP_BPF/CAP_SYS_ADMIN/root privileges were used.

## Common Commands

bpftool:

```bash
sudo bpftool -d prog load prog.o /sys/fs/bpf/prog 2>&1 | tee verifier.log
bpfix --format both verifier.log
bpfix --object prog.o --format json verifier.log > bpfix-diagnostic.json
```

libbpf or libbpf-rs project:

```bash
make load 2>&1 | tee load.log
bpfix load.log
```

Aya loader:

```bash
RUST_LOG=debug cargo run --bin loader 2>&1 | tee aya-load.log
bpfix aya-load.log
```

BCC tool:

```bash
sudo python3 tool.py 2>&1 | tee bcc-load.log
bpfix bcc-load.log
```

CI artifact pattern:

```bash
make load 2>&1 | tee verifier.log
bpfix --format json --fail-on-unsupported verifier.log > bpfix-diagnostic.json
```

If `bpfix` exits with code 2 under `--fail-on-unsupported`, inspect the JSON and
the raw log. The diagnostic artifact was still written; the problem is log
collection or unsupported-message coverage, not necessarily a source repair.

## Incomplete Logs

Before editing source, recollect the log when:

- BPFix reports `BPFIX-E000` or `unsupported_input`.
- The log lacks per-instruction lines such as `R1=ctx` or `R2=pkt_end`.
- The log only contains `invalid argument`, `permission denied`, or
  `program load failed`.
- CI truncated the middle of the verifier output.
- The terminal error mentions a helper/kfunc but the call target is missing.
