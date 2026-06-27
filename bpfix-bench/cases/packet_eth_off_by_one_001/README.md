# packet_eth_off_by_one_001

The program checks that 13 bytes of the Ethernet header are present and then
reads the 2-byte `h_proto` field at offset 12. The verifier needs proof for 14
bytes, so the final packet access is one byte beyond the proven range.

This is a packet range proof case. A correct repair must widen the exact
`data_end` guard and preserve IPv4 drop, non-IPv4 pass, and short-packet pass
behavior.
