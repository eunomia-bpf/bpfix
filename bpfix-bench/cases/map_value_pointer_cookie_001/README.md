# map_value_pointer_cookie_001

Canary bucket: proof lifecycle / map-value provenance.

The program parses Ethernet/IPv4, looks up a map value, checks the nullable
result, and then incorrectly treats the map-value pointer as an integer cookie
with inline assembly shifts before reading `drop_proto`.

The raw verifier log rejects the pointer shift:

```text
pointer arithmetic with <<= operator prohibited
```

A working repair must preserve the map lookup, keep the map-value pointer as a
verifier-visible pointer, increment `seen_packets`, read `drop_proto` from the
map value, and use that field to decide whether to drop the packet. The oracle
updates the pinned map with a protocol value unknown to the prompt, requires a
successful verifier trace with a map lookup plus map-value load/store evidence,
and runs IPv4/non-IPv4 packet tests.
