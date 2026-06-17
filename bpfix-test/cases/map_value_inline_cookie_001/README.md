# map_value_inline_cookie_001

Map-value provenance case with an inline lookup helper and packet-derived return
decision. The rejected operation is a pointer-cookie round trip on a non-null map
value. Correct repairs must keep the inline helper structure, dynamic map
configuration, map update, and per-protocol return semantics.
