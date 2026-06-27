# rs_datrail_cgroup_filter_key_width_001

Source: real project seed from `datrail-agent-monitor` commit
`cfd94492b336c70c680718ad6d91ca2a81cc048d`,
`bpf/process_ext/bpf_common.h`, license `GPL-2.0 OR BSD-3-Clause`.
Canonical source:
`https://github.com/DatRail/datrail-agent-monitor/blob/cfd94492b336c70c680718ad6d91ca2a81cc048d/bpf/process_ext/bpf_common.h`.
Upstream source sha256:
`f4d8232d42745a2ed3f6f31ecc67ca850ffec0a398539465ea79ad3a71d7a552`.

The upstream helper implements DatRail's event filter: trace everything when
cgroup filtering is disabled, accept the target cgroup directly, and otherwise
look up child cgroups in a `tracked_cgroups` map before allowing the event.
This minimized candidate keeps that cgroup-child filtering shape in an XDP
harness so the oracle can run deterministic packets.
It is a minimized mutation of that workflow, not a claim that the upstream
DatRail source contains this exact bug.

The harness models a tenant-scoped child-cgroup table: the packet carries a
tenant byte and a child selector byte, and the child lookup key is the 64-bit
pair `(tenant << 32) | selector`. The bug narrows the child lookup key into a
32-bit stack slot, then passes that address to `bpf_map_lookup_elem()` for a map
whose key is 64 bits. The verifier therefore rejects an 8-byte helper read from
a stack slot that only has a 4-byte initialization proof. The final error points
at the helper's indirect stack read, but the source mistake is the key-width
proof loss before the tenant-scoped map lookup.

A correct repair must initialize the same tenant-scoped 64-bit key for the child
lookup while preserving the `filter_cgroup_children` workflow, the
`tracked_cgroups` map lookup, packet-driven allow/drop behavior, and the
aggregate state update on tracked children. Merely widening the selector to
64 bits without carrying the tenant namespace loads but breaks the oracle.
Removing the lookup, changing the map schema, or returning a constant action is
not a valid repair.
