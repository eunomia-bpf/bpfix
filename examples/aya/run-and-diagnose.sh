#!/usr/bin/env bash
set -u

log=${LOG:-verifier.log}

if [ "$#" -eq 0 ]; then
  set -- cargo run --bin loader
fi

set +e
RUST_LOG=${RUST_LOG:-debug} "$@" 2>&1 | tee "$log"
load_status=${PIPESTATUS[0]}
set -e

if [ "$load_status" -ne 0 ]; then
  bpfix "$log"
fi

exit "$load_status"
