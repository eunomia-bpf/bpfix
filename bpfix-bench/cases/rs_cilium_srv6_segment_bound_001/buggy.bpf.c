#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef NEXTHDR_ROUTING
#define NEXTHDR_ROUTING 43
#endif
#ifndef NEXTHDR_UDP
#define NEXTHDR_UDP 17
#endif
#ifndef IPV6_SRCRT_TYPE_4
#define IPV6_SRCRT_TYPE_4 4
#endif

#define RS_SRV6_DROP_TAG 0xc1a01234U

struct rs_srv6_srh {
    __u8 nexthdr;
    __u8 hdrlen;
    __u8 type;
    __u8 segments_left;
    __u8 first_segment;
    __u8 flags;
    __u16 reserved;
    struct in6_addr segments[0];
};

static __always_inline int rs_srv6_first_segment_tag(void *cursor, void *data_end,
                                                     __u8 *nexthdr, __u32 *tag)
{
    struct rs_srv6_srh *srh = cursor;
    struct in6_addr *sid;

    if (*nexthdr != NEXTHDR_ROUTING)
        return 0;

    if ((void *)(srh + 1) > data_end)
        return -1;
    if (srh->type != IPV6_SRCRT_TYPE_4)
        return -1;

    *nexthdr = srh->nexthdr;
    if (srh->segments_left == 0)
        return 0;

    sid = &srh->segments[0];
    *tag = bpf_ntohl(sid->in6_u.u6_addr32[3]);
    return 1;
}

SEC("xdp")
int rs_cilium_srv6_segment_bound(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6;
    __u32 tag = 0;
    __u8 nexthdr;
    int ret;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6)
        return XDP_PASS;

    ip6 = data + sizeof(*eth);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    nexthdr = ip6->nexthdr;
    ret = rs_srv6_first_segment_tag((void *)(ip6 + 1), data_end, &nexthdr, &tag);
    if (ret <= 0)
        return XDP_PASS;

    return tag == RS_SRV6_DROP_TAG ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
