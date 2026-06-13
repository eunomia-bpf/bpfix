# libbpf C

Use this when your loader opens and loads an object with libbpf directly or via
a generated skeleton.

For a direct `bpf_object__open_file()` path, `loader-snippet.c` shows how to
provide a verifier log buffer:

```c
LIBBPF_OPTS(bpf_object_open_opts, opts,
    .kernel_log_buf = verifier_log,
    .kernel_log_size = sizeof(verifier_log),
    .kernel_log_level = 2,
);
```

After `bpf_object__load(obj)` fails, write that buffer to `verifier.log` and run:

```bash
bpfix --object xdp.o verifier.log
```

For skeleton-based loaders, keep the skeleton flow unchanged and capture the
loader's stderr/stdout:

```bash
./loader 2>&1 | tee verifier.log
bpfix verifier.log
```
