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
editor/diagnostic.schema.example.json
editor/json-output.sh
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

find "$examples_dir" -name '*.sh' -type f -print | sort | while IFS= read -r script; do
    bash -n "$script"
done

python3 -m json.tool "$examples_dir/editor/diagnostic.schema.example.json" >/dev/null
python3 -m json.tool "$repo_root/docs/evaluation/diagnostic.schema.json" >/dev/null

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
