# bpftool

Use this when you already load a compiled eBPF object with `bpftool`.

```bash
./examples/bpftool/load-and-diagnose.sh xdp.o /sys/fs/bpf/xdp
```

The important pieces are:

```bash
sudo bpftool -d prog load xdp.o /sys/fs/bpf/xdp 2>&1 | tee verifier.log
bpfix verifier.log
```

`-d` asks bpftool/libbpf to emit debug output, including the verifier log when
the load fails.

Object metadata is optional and experimental. If BPFix was installed with
`--features object-analysis`, opt into it explicitly:

```bash
BPFIX_OBJECT_ANALYSIS=1 ./examples/bpftool/load-and-diagnose.sh xdp.o /sys/fs/bpf/xdp
```
