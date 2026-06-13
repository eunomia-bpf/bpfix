# bpftool

Use this when you already load a compiled eBPF object with `bpftool`.

```bash
./examples/bpftool/load-and-diagnose.sh xdp.o /sys/fs/bpf/xdp
```

The important pieces are:

```bash
sudo bpftool -d prog load xdp.o /sys/fs/bpf/xdp 2>&1 | tee verifier.log
bpfix --object xdp.o verifier.log
```

`-d` asks bpftool/libbpf to emit debug output, including the verifier log when
the load fails. Passing `--object` is optional, but lets BPFix attach bytecode
metadata when the object layout matches the verifier program.
