# CI

CI should keep the original build or load step visible, then upload both the
raw verifier log and BPFix JSON when the load fails.

The GitHub Actions example does three things:

1. Runs the normal build/load command.
2. On failure, runs `bpfix --format json --fail-on-unsupported`.
3. Uploads `verifier.log` and `bpfix-diagnostic.json` as artifacts.

The diagnostic step uses `continue-on-error` so unsupported input still leaves a
JSON diagnostic artifact behind. The final step fails the job after upload,
preserving the original verifier failure while making BPFix's own diagnostic
status visible.

Copy `github-actions.yml` into `.github/workflows/bpfix.yml` and replace
`make build`, `xdp.o`, and `/sys/fs/bpf/xdp` with your project commands.
