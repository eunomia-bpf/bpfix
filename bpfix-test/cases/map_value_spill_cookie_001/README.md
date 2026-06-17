# map_value_spill_cookie_001

Map-value pointer provenance is established by `bpf_map_lookup_elem()`, kept
through an explicit null check, spilled through a local variable, then destroyed
by pointer-as-integer inline assembly before the value fields are accessed.

The oracle requires the repair to keep the map lookup, preserve the map-value
field reads/writes, and keep the protocol-dependent XDP behavior.
