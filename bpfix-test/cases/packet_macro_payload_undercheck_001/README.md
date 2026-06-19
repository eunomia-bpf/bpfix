# packet_macro_payload_undercheck_001

The program uses a macro to guard a UDP header pointer reached through the
packet's variable IPv4 header length. The macro checks only seven bytes before
the code reads the two-byte checksum field at offset six. The verifier needs
proof for eight bytes at the variable UDP base.

This is a source-correlation packet bounds case. A correct repair must fix the
macro-sized guard or add an exact check while preserving the variable-IHL UDP
base, DNS-like checksum drop, ordinary UDP pass, TCP pass, and truncated-packet
pass behavior.
