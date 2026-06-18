# rs_cilium_mcast_igmpv3_grec_bound_001

Real-project seed from Cilium's `bpf/lib/mcast.h` IGMPv3 multicast group-record
handler. The case preserves the IPv4 multicast parsing shape and the unrolled
group-record loop in a deterministic XDP harness.

The buggy program checks only the IGMPv3 report header, then reads each
`igmpv3_grec` record in an unrolled loop without the per-record packet bound
check that Cilium's implementation documents as verifier-required. A correct
repair must keep the group-record loop and add a dominating record bound check
before reading `grec_type` and `grec_mca`.
