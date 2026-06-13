# Make

Use this when a project already has a target such as `make load`,
`make run`, or `make test` that eventually loads an eBPF program.

Copy the targets from `Makefile.snippet` into the project Makefile, or run the
same command pattern directly:

```bash
make load 2>&1 | tee verifier.log
bpfix verifier.log
```

This keeps the existing build system responsible for compiling and loading the
program. BPFix only reads the produced log.
