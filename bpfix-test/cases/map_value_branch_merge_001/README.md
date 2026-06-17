# map_value_branch_merge_001

Canary bucket: proof lifecycle / map value nullability.

The program looks up an array-map value, checks the nullable result only on one
branch, and then reads the map value after a branch merge. The verifier rejects
the merged path because the `map_value_or_null` proof is not established on all
paths.

A working repair must preserve the packet parser and map lookup, prove the map
value non-null before the common read, and still use the map's `drop_proto`
field to decide whether to drop the packet.
