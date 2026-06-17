# helper_map_arg_stack_001

The program declares a real map but accidentally passes `&key` as both
arguments to `bpf_map_lookup_elem()`. The first helper argument must be the map
object, not a stack pointer.

This is a helper contract case. A correct repair must pass `&configs` as the
map argument, keep the initialized key, and preserve the map-driven IPv4 drop
and non-IPv4 pass behavior.
