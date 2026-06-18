# rs_cilium_ip_options_traceid_payload_bound_001

Source: real project seed from Cilium commit
`3a3646386538766d6edd5ada929b427728dbfafd`,
`bpf/lib/ip_options.h`, license `(GPL-2.0-only OR BSD-2-Clause)`.
Canonical source:
`https://github.com/cilium/cilium/blob/3a3646386538766d6edd5ada929b427728dbfafd/bpf/lib/ip_options.h`.
Upstream source sha256:
`a3d873c58032ebda0f4dcb698377d7dc73816d019f0a0824cfbc62f8a116ea9c`.

The upstream parser walks IPv4 options, handles END/NOOP options, accepts only
supported trace-id option lengths, and reads a 16/32/64-bit trace id from the
option payload. This minimized XDP harness preserves that parser shape with an
inline helper and an unrolled option loop, but uses deterministic packet return
values instead of Cilium tracing state.

This case is a minimized mutation of the parser workflow, not a claim that the
upstream Cilium code contains this exact bug. The bug checks only the option
header before reading the 16-bit trace-id payload. After an earlier option shifts
the option pointer by a packet-derived length, the final verifier rejection
points at the trace-id load, while the root cause is the missing payload bound
proof for the loop-derived option pointer.

A correct repair must prove the full trace-id payload before reading it, keep
END/NOOP option handling, preserve the 16/32/64-bit supported-length contract,
and still return `XDP_DROP` only for the configured trace id. Returning a
constant action, dropping all UDP packets, or bypassing the option-loop parser is
not a valid repair.
