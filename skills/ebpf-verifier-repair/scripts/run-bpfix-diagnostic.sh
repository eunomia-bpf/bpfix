#!/usr/bin/env bash
set -u

usage() {
  cat <<'USAGE'
Usage: run-bpfix-diagnostic.sh [--object OBJ] [--out DIR] [--bpfix PATH] LOG

Run bpfix on a verifier/build/load log and write a plain-text diagnostic.

Options:
  --object OBJ   Optional compiled BPF object passed to bpfix --object.
  --out DIR      Output directory. Defaults to .bpfix-agent.
  --bpfix PATH   bpfix executable path. Defaults to $BPFIX_BIN, bpfix on PATH,
                 or cargo run -q -p bpfix -- from a BPFix checkout.
USAGE
}

out_dir=".bpfix-agent"
object_path=""
bpfix_path="${BPFIX_BIN:-}"
log_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --object)
      [[ $# -ge 2 ]] || { echo "missing value for --object" >&2; exit 64; }
      object_path="$2"
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || { echo "missing value for --out" >&2; exit 64; }
      out_dir="$2"
      shift 2
      ;;
    --bpfix)
      [[ $# -ge 2 ]] || { echo "missing value for --bpfix" >&2; exit 64; }
      bpfix_path="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 64
      ;;
    *)
      if [[ -n "$log_path" ]]; then
        echo "unexpected extra argument: $1" >&2
        usage >&2
        exit 64
      fi
      log_path="$1"
      shift
      ;;
  esac
done

if [[ $# -gt 0 ]]; then
  if [[ -n "$log_path" ]]; then
    echo "unexpected extra argument: $1" >&2
    usage >&2
    exit 64
  elif [[ $# -gt 1 ]]; then
    echo "unexpected extra argument: $2" >&2
    usage >&2
    exit 64
  fi
  log_path="$1"
fi

if [[ -z "$log_path" ]]; then
  usage >&2
  exit 64
fi

if [[ ! -f "$log_path" ]]; then
  echo "log file not found: $log_path" >&2
  exit 66
fi

if [[ -n "$object_path" && ! -f "$object_path" ]]; then
  echo "object file not found: $object_path" >&2
  exit 66
fi

run_bpfix() {
  if [[ -n "$bpfix_path" ]]; then
    "$bpfix_path" "$@"
  elif command -v bpfix >/dev/null 2>&1; then
    bpfix "$@"
  elif [[ -f Cargo.toml ]] && grep -q "bpfix" Cargo.toml; then
    cargo run -q -p bpfix -- "$@"
  else
    echo "bpfix not found; install with 'cargo install bpfix' or set BPFIX_BIN" >&2
    return 127
  fi
}

mkdir -p "$out_dir" || exit 73
text_out="$out_dir/diagnostic.txt"

common_args=()
if [[ -n "$object_path" ]]; then
  common_args+=(--object "$object_path")
fi

text_status=0
run_bpfix "${common_args[@]}" --fail-on-unsupported "$log_path" > "$text_out" || text_status=$?

echo "text: $text_out"

if [[ $text_status -eq 2 ]]; then
  echo "bpfix reported unsupported input/message; inspect artifacts before editing source" >&2
  exit 2
elif [[ $text_status -ne 0 ]]; then
  echo "bpfix rendering failed with exit code $text_status" >&2
  exit "$text_status"
fi
