# rs_xdp_tools_xdpdump_perf_map_type_001

Real-project seed candidate from xdp-tools `xdpdump_xdp.c`.
The minimized program keeps the XDP packet-metadata capture path and the
`bpf_perf_event_output()` workflow used by xdpdump, but the buggy perf-output
map is declared as a plain array instead of `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.

The verifier rejects the helper call because the helper contract requires a perf
event array map. A correct repair must restore the map type while preserving the
packet length metadata and the perf-event output helper call. The oracle checks
that fixed candidates still load as XDP, return `XDP_PASS` for representative
packets, and reach `bpf_perf_event_output()` with the xdpdump perf map.
