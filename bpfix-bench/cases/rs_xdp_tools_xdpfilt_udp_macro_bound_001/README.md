# rs_xdp_tools_xdpfilt_udp_macro_bound_001

Real-project seed candidate from xdp-tools `xdp-filter/xdpfilt_prog.h`.
The minimized program preserves the xdp-filter style of parsing through
`struct hdr_cursor`, `__always_inline` header parsers, and macro-expanded
verdict checks.

The buggy program correctly parses Ethernet and variable-length IPv4 headers,
then casts the cursor to `struct udphdr *` and reads `udp->dest` through a
macro without first proving the UDP header bound. The verifier rejects the
macro-expanded packet read. A correct repair must add the missing UDP parser
or an equivalent dominating UDP-header bound while preserving variable-IHL
IPv4 handling, the DNS drop decision, and non-UDP/pass behavior.
