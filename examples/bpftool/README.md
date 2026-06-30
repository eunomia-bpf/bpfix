# bpftool

Use this when you already load a compiled eBPF object with `bpftool`.

```bash
./examples/bpftool/load-and-diagnose.sh
```

The important pieces are:

```bash
sudo bpftool -d prog load examples/bpftool/quick-start.bpf.o /sys/fs/bpf/bpfix-demo 2>&1 | tee verifier.log
bpfix verifier.log
```

`-d` asks bpftool/libbpf to emit debug output, including the verifier log when
the load fails. The committed `quick-start.bpf.o` is copied from
`bpfix-empirical/cases/stackoverflow-53136145/prog.o`, the same case used by the
root README Quick Start.

Object metadata is optional. If BPFix was installed with `--features
object-analysis`, opt into it explicitly:

```bash
BPFIX_OBJECT_ANALYSIS=1 ./examples/bpftool/load-and-diagnose.sh
```
