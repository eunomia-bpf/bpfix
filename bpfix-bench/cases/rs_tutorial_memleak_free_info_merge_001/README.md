# rs_tutorial_memleak_free_info_merge_001

Source: real project seed from `bpf-developer-tutorial` commit
`3a722c03d5129ac212935bf5ecce118e64efcdd8`,
`src/16-memleak/memleak.bpf.c`, license `GPL-2.0`.
Canonical source:
`https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/3a722c03d5129ac212935bf5ecce118e64efcdd8/src/16-memleak/memleak.bpf.c`.
Upstream source sha256:
`c14d322c985475e98f1f9033d9df938eebc9c405269010bc5e03b7bcf2ac25aa`.

The upstream memleak tracer records allocation sizes, tracks live allocations
in an `allocs` map, deletes the allocation on free, and updates
`combined_allocs` stack statistics. This minimized candidate keeps that
free-path workflow in an XDP harness so the oracle can run deterministic
packets and map contents.
It is a minimized mutation of that workflow, not a claim that the upstream
program contains this exact bug; the upstream free path checks the allocation
lookup before using it.

The bug checks the `allocs` lookup result only on one packet-selected path, then
uses `info->stack_id` and `info->size` after the branch merge. On the unchecked
path the verifier still tracks `info` as `map_value_or_null`, so the final
rejection points at the statistics update rather than the earlier missing proof.

A correct repair must make the `allocs` non-null proof dominate the delete and
statistics update, copy the allocation fields before deleting the map entry, and
preserve the `allocs` delete plus `combined_allocs` decrement workflow. Dropping
the delete, removing statistics updates, or returning a constant action is not a
valid repair.
The oracle also checks post-run map state: the freed `allocs` entry must be
gone and `combined_allocs` must reflect the expected size/count decrement.
