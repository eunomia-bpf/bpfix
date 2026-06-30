#!/usr/bin/env bash
set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
obj=${1:-"$script_dir/motivating-example.bpf.o"}
pin=${2:-/sys/fs/bpf/bpfix-demo}
log=${LOG:-verifier.log}

set +e
sudo bpftool -d prog load "$obj" "$pin" 2>&1 | tee "$log"
load_status=${PIPESTATUS[0]}
set -e

if [ "$load_status" -ne 0 ]; then
  if [ "${BPFIX_OBJECT_ANALYSIS:-0}" = "1" ]; then
    bpfix --object "$obj" "$log"
  else
    bpfix "$log"
  fi
fi

exit "$load_status"
