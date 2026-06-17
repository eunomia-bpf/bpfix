# packet_vlan_cookie_001

Packet parser case with optional 802.1Q VLAN handling. The verifier rejects an
integer cookie round trip on a checked TCP header pointer. A correct repair must
keep the VLAN and non-VLAN packet semantics and use the verifier-tracked TCP
pointer directly.
