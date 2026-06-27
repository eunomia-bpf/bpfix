# packet_ihl_udp_undercheck_001

The program parses IPv4 packets with variable IHL and computes the UDP header
address from that packet-controlled header length. It checks only three bytes
past the computed UDP pointer and then reads the two-byte destination port at
offset 2, which requires four bytes.

This is a scalar/range packet proof case. A correct repair must check the exact
UDP field width at the variable L4 pointer and preserve normal UDP, IP-options,
non-DNS, and truncated-packet behavior.
