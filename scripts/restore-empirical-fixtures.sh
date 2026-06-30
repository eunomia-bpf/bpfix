#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)
ARCHIVE="${REPO_ROOT}/bpfix-empirical/empirical-fixtures.tar.gz"

if [[ ! -f "${ARCHIVE}" ]]; then
    echo "missing empirical fixture archive: ${ARCHIVE}" >&2
    exit 1
fi

tar --extract \
    --gzip \
    --file "${ARCHIVE}" \
    --directory "${REPO_ROOT}" \
    --transform='s#^bpfix-bench/#bpfix-empirical/#'

python3 - "${REPO_ROOT}" <<'PY'
import pathlib
import re
import sys

repo_root = pathlib.Path(sys.argv[1])
tests = repo_root / "crates/bpfix/src/diagnostic/tests.rs"
text = tests.read_text(encoding="utf-8")
missing = []
for rel in sorted(set(re.findall(r'"\.\./\.\./\.\./\.\./(bpfix-empirical/cases/[^"]+replay-verifier\.log)"', text))):
    if not (repo_root / rel).is_file():
        missing.append(rel)

if missing:
    print("empirical fixture archive did not restore required replay logs:", file=sys.stderr)
    for rel in missing:
        print(f"  {rel}", file=sys.stderr)
    raise SystemExit(1)
PY
