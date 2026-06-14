#!/usr/bin/env bash
set -u

loader=${1:-./target/debug/loader}
object=${2:-}
log=${LOG:-verifier.log}

set +e
"$loader" 2>&1 | tee "$log"
load_status=${PIPESTATUS[0]}
set -e

if [ "$load_status" -ne 0 ]; then
  if [ "${BPFIX_OBJECT_ANALYSIS:-0}" = "1" ] && [ -n "$object" ]; then
    bpfix --object "$object" "$log"
  else
    bpfix "$log"
  fi
fi

exit "$load_status"
