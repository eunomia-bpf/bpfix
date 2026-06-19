# map_value_branch_merge_001

Bucket: proof lifecycle / map value nullability with policy fallback semantics.

The program looks up a default hash-map policy, proves it non-null, and parses an
IPv4 protocol byte. On UDP packets it tries to use a protocol-specific override
entry. The bug overwrites the proven default pointer with the nullable override
lookup result and then reads the policy after the merge. The verifier rejects the
common read because the `map_value_or_null` proof for the override lookup is not
established on all paths.

A working repair must preserve the packet parser, keep the default policy as a
fallback when the UDP override entry is absent, update `seen_udp` on the selected
policy, and still use the selected policy's `drop_proto` field to decide whether
to drop the packet. Simply returning `XDP_PASS` when the override lookup is null
loads successfully but is not a valid repair.
