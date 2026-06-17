# map_value_index_guard_oob_001

The map value contains two `u32` slots. The packet protocol selects an index in
`0..3`, but the guard only rejects values greater than 2. That still allows
`idx == 2`, so `cfg->slots[idx]` can cross the declared map value size.

This is a map-value bounds proof case. A correct repair must guard the exact
array length and preserve map-driven behavior for valid indexes while passing
out-of-range packet-derived indexes.
