#!/usr/bin/env bash
set -u

obj=${1:-xdp.o}
pin=${2:-/sys/fs/bpf/bpfix_example}
log=${LOG:-verifier.log}

set +e
sudo bpftool -d prog load "$obj" "$pin" 2>&1 | tee "$log"
load_status=${PIPESTATUS[0]}
set -e

if [ "$load_status" -ne 0 ]; then
  bpfix --object "$obj" "$log"
fi

exit "$load_status"
