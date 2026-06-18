# rs_eunomia_http_doff_copy_bound_001

Real-project seed candidate from eunomia.dev
`docs/tutorials/23-http/sockfilter.bpf.c`. The minimized program keeps the
HTTP socket-filter parser shape: parse Ethernet/IPv4/TCP, handle variable IPv4
header length, derive a TCP payload/capture offset from `doff`, and emit a
ringbuf record. The XDP harness uses a stats map only as executable oracle
instrumentation.

The injected bug proves only the fixed 20-byte TCP header before an unrolled
copy that may read up to the doff-derived capture window. The verifier rejects
one of the copied bytes because the packet range proof does not dominate the
ringbuf copy.
A correct repair must provide a verifier-visible packet bound for the capture
window while preserving variable `doff` semantics, ringbuf submit, IPv4 option
handling, truncated-packet pass-through, and stats-map side effects.
