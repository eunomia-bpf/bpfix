#!/usr/bin/env bash
set -u

log=${1:-verifier.log}
out=${2:-bpfix-diagnostic.json}

bpfix --format json "$log" > "$out"
printf 'wrote %s\n' "$out"
