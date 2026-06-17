# packet_inline_return_cookie_001

Packet provenance case where the bounds proof is hidden behind an inline parser
that returns a UDP pointer. The caller validates the returned pointer, then
destroys verifier provenance with an integer cookie before reading the UDP
destination port.
