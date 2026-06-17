#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)
ARCHIVE="${REPO_ROOT}/bpfix-bench/benchmark-fixtures.tar.gz"

if [[ ! -f "${ARCHIVE}" ]]; then
    echo "missing benchmark fixture archive: ${ARCHIVE}" >&2
    exit 1
fi

tar -xzf "${ARCHIVE}" -C "${REPO_ROOT}"
