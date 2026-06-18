# rs_cilium_ipv6_exthdr_l4_offset_001

This candidate is a minimized real-project seed from Cilium's IPv6 extension
header parser (`bpf/lib/ipv6.h`). The upstream code uses inline helpers to walk
IPv6 extension headers and return the final L4 offset.

The minimized program keeps that source/object-correlation shape in an XDP
packet filter. It reads the IPv6 next-header field, optionally skips one
hop-by-hop extension header using a Cilium-style inline helper, and then applies
a UDP destination-port policy.

The bug is that the program validates the fixed L4 pointer immediately after
the IPv6 header, but reads the UDP header through the extension-derived variable
L4 pointer. For packets with a hop-by-hop extension header, the verifier sees
the final UDP read from a packet pointer whose variable offset is not bounded by
the checked pointer, so it rejects the program.

A correct repair must preserve IPv6 extension-header parsing and the UDP port
policy, and must prove bounds for the actual extension-derived L4 pointer before
reading `udp->dest`. Removing extension parsing or always reading the fixed
no-extension offset is not a correct repair.
