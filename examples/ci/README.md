# CI

CI should keep the original build or load step visible, then upload both the
raw verifier log and BPFix JSON when the load fails.

The GitHub Actions example does three things:

1. Runs the normal build/load command.
2. On failure, runs `bpfix --format json`.
3. Uploads `verifier.log` and `bpfix-diagnostic.json` as artifacts.

Copy `github-actions.yml` into `.github/workflows/bpfix.yml` and replace
`make build`, `xdp.o`, and `/sys/fs/bpf/xdp` with your project commands.
