# rs_cilium_srv6_segment_bound_001

Source: real project seed from Cilium commit
`3a3646386538766d6edd5ada929b427728dbfafd`,
`bpf/lib/srv6.h`, license `(GPL-2.0-only OR BSD-2-Clause)`.
Canonical source:
`https://github.com/cilium/cilium/blob/3a3646386538766d6edd5ada929b427728dbfafd/bpf/lib/srv6.h`.
Upstream source sha256:
`b392bde6b05f4c058f6e6a395c4b583f5e562732902790171d4cc95fffa6def1`.

The upstream SRv6 path parses an IPv6 routing header, validates that the SRH
extension header is present, accepts only SRH type 4, and then handles the
segment list. This minimized XDP harness preserves that header shape and the
first-segment decision but uses deterministic XDP return values instead of
Cilium tail calls and packet rewriting.

This case is a minimized mutation of the SRv6 parsing workflow, not a claim
that the upstream Cilium code contains this exact bug. The bug proves only the
fixed SRH header before reading `segments[0]`. The final verifier rejection
points at the SID tag load, while the missing proof is the segment-list bound
that must be established after the SRH type and `segments_left` checks.

A correct repair must prove the full first SID before reading it, preserve SRH
type-4 filtering, preserve the `segments_left == 0` pass-through behavior, and
return `XDP_DROP` only for the configured SID tag. Returning a constant action,
dropping all routing-header packets, or bypassing the segment-list parser is not
a valid repair.
