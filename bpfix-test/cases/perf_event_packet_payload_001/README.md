# perf_event_packet_payload_001

The program passes the packet data pointer directly as the payload to
`bpf_perf_event_output()`. The helper cannot read live packet memory through
that argument.

This is a helper data-source contract case. A correct repair must copy the
packet bytes into helper-readable stack storage before calling the perf-event
helper and preserve packet return behavior.
