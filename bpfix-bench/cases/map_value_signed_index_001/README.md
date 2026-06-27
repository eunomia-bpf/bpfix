# map_value_signed_index_001

The packet-controlled index is sign-extended from an 8-bit field. The code
checks only the upper bound (`idx < 2`) before indexing a two-slot map value,
so negative indexes can move the map-value pointer before the object.

This is a scalar signed-range map-value case. A correct repair must prove both
lower and upper bounds for the exact signed index while preserving valid slot
behavior and negative-index pass behavior.
