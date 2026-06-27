# rs_xdp_tools_xdpsock_redirect_map_type_001

Real-project seed candidate from xdp-tools `lib/util/xdpsock.bpf.c`.
The minimized program keeps the XDP socket redirect workflow: a per-packet
round-robin socket index is updated and then passed to `bpf_redirect_map()`.

The buggy program declares `xsks_map` as a normal array instead of
`BPF_MAP_TYPE_XSKMAP`. The verifier rejects the helper call because XDP socket
redirect requires a redirect-capable map. A correct repair must restore the map
contract while preserving the round-robin state update, the sentinel pass path,
and the redirect helper's `XDP_DROP` fallback behavior.
