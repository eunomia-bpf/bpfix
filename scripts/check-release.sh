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

require_package_file() {
    local crate=$1
    local manifest=$2
    local path=$3

    if ! printf '%s\n' "${manifest}" | grep -Fqx "${path}"; then
        echo "${crate} package is missing required file: ${path}" >&2
        exit 1
    fi
}

reject_package_paths() {
    local crate=$1
    local manifest=$2

    if printf '%s\n' "${manifest}" | grep -Eq '^(bpfix-bench|docs/tmp|vendor|docs/project-status\.md)(/|$)'; then
        echo "${crate} package includes non-release project material:" >&2
        printf '%s\n' "${manifest}" |
            grep -E '^(bpfix-bench|docs/tmp|vendor|docs/project-status\.md)(/|$)' >&2
        exit 1
    fi
}

bpfanalysis_manifest=$(cargo package -p bpfanalysis --list "${package_flags[@]}")
require_package_file bpfanalysis "${bpfanalysis_manifest}" Cargo.toml
require_package_file bpfanalysis "${bpfanalysis_manifest}" src/lib.rs
require_package_file bpfanalysis "${bpfanalysis_manifest}" src/verifier_log.rs
reject_package_paths bpfanalysis "${bpfanalysis_manifest}"

bpfix_manifest=$(cargo package -p bpfix --list "${package_flags[@]}")
require_package_file bpfix "${bpfix_manifest}" Cargo.toml
require_package_file bpfix "${bpfix_manifest}" README.md
require_package_file bpfix "${bpfix_manifest}" src/main.rs
require_package_file bpfix "${bpfix_manifest}" tests/cli.rs
reject_package_paths bpfix "${bpfix_manifest}"

examples/check-examples.sh
python3 bpfix-bench/run-bpfix-eval.py --confusion --coverage --reject-fallback
cargo test -p bpfix --features object-analysis --test cli
cargo package -p bpfanalysis "${package_flags[@]}"

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
