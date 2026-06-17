#!/usr/bin/env bash
set -euo pipefail

: "${CRATE_NAME:?CRATE_NAME is required}"
: "${CRATE_VERSION:?CRATE_VERSION is required}"

echo "Waiting for ${CRATE_NAME} ${CRATE_VERSION} to appear in crates.io index..."

for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if python3 - <<'PY'
import json
import os
import urllib.error
import urllib.request

crate = os.environ["CRATE_NAME"]
version = os.environ["CRATE_VERSION"]
req = urllib.request.Request(
    f"https://crates.io/api/v1/crates/{crate}/{version}",
    headers={"User-Agent": "bpfix-release-ci"},
)
try:
    with urllib.request.urlopen(req, timeout=30) as response:
        json.load(response)
except urllib.error.HTTPError as exc:
    if exc.code == 404:
        raise SystemExit(1)
    raise
PY
    then
        echo "Found ${CRATE_NAME} ${CRATE_VERSION}"
        exit 0
    fi

    echo "Attempt ${attempt}/12..."
    if [ "${attempt}" -eq 12 ]; then
        break
    fi
    sleep 10
done

echo "${CRATE_NAME} ${CRATE_VERSION} did not appear in crates.io index"
exit 1
