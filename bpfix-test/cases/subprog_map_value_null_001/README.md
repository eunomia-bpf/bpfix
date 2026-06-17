# subprog_map_value_null_001

The map lookup is hidden behind a `__noinline` BPF subprogram. The caller treats
the returned `map_value_or_null` as non-null and reads `drop_proto` directly.

This is a source/object correlation and nullable proof case. A correct repair
must check the subprogram return value in the caller while preserving the
subprogram structure and map-driven packet behavior.
