#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)
cd "${REPO_ROOT}"

package_flags=()
if ! git diff-index --quiet HEAD --; then
    package_flags+=(--allow-dirty)
    echo "warning: packaging a dirty worktree; commit before publishing" >&2
fi

bpfanalysis_version=$(
    sed -n 's/^version = "\(.*\)"/\1/p' crates/bpfanalysis/Cargo.toml | head -n 1
)
bpfix_version=$(
    sed -n 's/^version = "\(.*\)"/\1/p' crates/bpfix/Cargo.toml | head -n 1
)

if [[ -z "${bpfanalysis_version}" || -z "${bpfix_version}" ]]; then
    echo "failed to read crate versions" >&2
    exit 1
fi

expected_dependency="bpfanalysis = { version = \"${bpfanalysis_version}\", path = \"../bpfanalysis\", default-features = false }"
if ! grep -Fqx "${expected_dependency}" crates/bpfix/Cargo.toml; then
    echo "bpfix must depend on the matching publishable bpfanalysis version:" >&2
    echo "  ${expected_dependency}" >&2
    exit 1
fi

cargo package -p bpfanalysis "${package_flags[@]}"
cargo package -p bpfix --list "${package_flags[@]}" >/dev/null

cat <<EOF
release check passed

Publish order:
  1. cargo publish -p bpfanalysis
  2. wait for bpfanalysis ${bpfanalysis_version} to appear in the crates.io index
  3. cargo publish -p bpfix

bpfix ${bpfix_version} cannot be fully package-verified before bpfanalysis
${bpfanalysis_version} is available from crates.io, because Cargo removes path
dependencies from published packages.
EOF
