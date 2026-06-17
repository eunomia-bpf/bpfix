# packet_macro_payload_undercheck_001

The program uses a macro to guard a UDP header pointer, but the macro checks
only seven bytes before the code reads the two-byte checksum field at offset
six. The verifier needs proof for eight bytes.

This is a source-correlation packet bounds case. A correct repair must fix the
macro-sized guard or add an exact check while preserving DNS-like checksum
drop, ordinary UDP pass, TCP pass, and truncated-packet pass behavior.
