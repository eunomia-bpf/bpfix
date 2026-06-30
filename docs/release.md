# Release Process

BPFix is released as two crates:

- `bpfanalysis`: verifier-log and BPF bytecode analysis primitives.
- `bpfix`: the user-facing CLI, which depends on the matching `bpfanalysis`
  version.

Both crates use the same SemVer version. The current release line is `0.1.x`.
Patch releases are appropriate for documentation, diagnostic coverage,
packaging, and CI fixes that preserve the CLI contract.

## Required Gates

Run the repository release gate before publishing:

```bash
make release-check
```

This gate checks package contents, example consistency, the user-facing error
catalog, the empirical diagnostic fallback gate, and the feature-gated
object-analysis CLI path.

CI also runs:

```bash
cargo fmt --all --check
examples/check-examples.sh
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build -p bpfix --no-default-features
scripts/check-release.sh
python3 bpfix-empirical/run-bpfix-eval.py --confusion --reject-fallback --no-build
```

## crates.io Automation

The `Publish to crates.io` GitHub Actions job runs after the test job on
`master`, `main`, or manual `workflow_dispatch`.

If the repository secret `CARGO_REGISTRY_TOKEN` is missing, the job exits
successfully after a warning and skips publishing. This keeps normal CI green
for forks and fresh checkouts.

When `CARGO_REGISTRY_TOKEN` is present, the workflow:

1. Queries crates.io for `bpfanalysis` and `bpfix`.
2. Selects the next patch version for which neither crate is published.
3. Updates `crates/bpfanalysis/Cargo.toml`, `crates/bpfix/Cargo.toml`, and
   `Cargo.lock`.
4. Commits `chore: release bpfix <version> [skip ci]`.
5. Publishes `bpfanalysis`.
6. Waits for the crates.io index to expose `bpfanalysis`.
7. Packages and publishes `bpfix`.
8. Smoke-tests `cargo install bpfix --version <version> --locked`.

## Manual Fallback

If automation is unavailable, use the same order:

```bash
make release-check
cargo publish -p bpfanalysis
# wait until crates.io exposes bpfanalysis at the selected version
cargo package -p bpfix
cargo publish -p bpfix
cargo install bpfix --version <version> --locked --force
bpfix --version
```

Do not publish `bpfix` before the matching `bpfanalysis` version is visible in
the crates.io index; Cargo removes local path dependencies from published
packages.
