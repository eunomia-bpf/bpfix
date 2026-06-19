#!/usr/bin/env bash
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
examples_dir="$repo_root/examples"

required_files="
README.md
aya/README.md
aya/loader-snippet.rs
aya/run-and-diagnose.sh
bcc/README.md
bcc/tool-snippet.py
bpftool/README.md
bpftool/load-and-diagnose.sh
ci/README.md
ci/github-actions.yml
editor/README.md
editor/write-diagnostic.sh
libbpf-c/README.md
libbpf-c/loader-snippet.c
libbpf-rs/README.md
libbpf-rs/run-and-diagnose.sh
make/README.md
make/Makefile.snippet
"

for file in $required_files; do
    test -f "$examples_dir/$file"
done

generated_files=$(find "$examples_dir" \( -name '__pycache__' -o -name '*.py[co]' \) -print)
if [ -n "$generated_files" ]; then
    echo "examples contain generated Python cache files:" >&2
    printf '%s\n' "$generated_files" >&2
    exit 1
fi

find "$examples_dir" -name '*.sh' -type f -print | sort | while IFS= read -r script; do
    bash -n "$script"
done

python3 - "$examples_dir/bcc/tool-snippet.py" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY
obsolete_pattern='bpfix capt(ure)?|capt(ure)? --|case\.yaml|BPFIX-UNK[N]OWN'
if rg -n "$obsolete_pattern" "$examples_dir" --glob '!check-examples.sh'; then
    echo "examples mention an obsolete public entrypoint or runtime benchmark artifact" >&2
    exit 1
fi

for file in \
    "$examples_dir/bpftool/load-and-diagnose.sh" \
    "$examples_dir/libbpf-rs/run-and-diagnose.sh" \
    "$examples_dir/make/Makefile.snippet"
do
    if rg -q "bpfix --object|\\$\\(BPFIX\\) --object" "$file" &&
       ! rg -q "BPFIX_OBJECT_ANALYSIS" "$file"; then
        echo "$file uses --object without an explicit BPFIX_OBJECT_ANALYSIS gate" >&2
        exit 1
    fi
done

if ! rg -q "bpfix verifier\\.log" "$examples_dir/README.md"; then
    echo "examples README must keep the log-first quickstart visible" >&2
    exit 1
fi

ci_workflow="$examples_dir/ci/github-actions.yml"
for pattern in \
    "--fail-on-unsupported" \
    "continue-on-error: true" \
    "if: always() && steps.load.outcome == 'failure'"
do
    if ! rg -q --fixed-strings -- "$pattern" "$ci_workflow"; then
        echo "CI example must preserve diagnostic artifacts while failing unsupported diagnostics: missing $pattern" >&2
        exit 1
    fi
done
