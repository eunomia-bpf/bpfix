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
#ifndef NEXTHDR_HOP
#define NEXTHDR_HOP 0
#endif
#ifndef NEXTHDR_UDP
#define NEXTHDR_UDP 17
#endif

struct cilium_ipv6_opt_hdr {
    __u8 nexthdr;
    __u8 hdrlen;
};

static __always_inline __u32 rs_cilium_ipv6_optlen(const struct cilium_ipv6_opt_hdr *opthdr)
{
    return ((__u32)opthdr->hdrlen + 1) << 3;
}

static __always_inline int rs_cilium_skip_hopopts(void *cursor, void *data_end,
                                                  __u8 *nexthdr, void **l4)
{
    struct cilium_ipv6_opt_hdr *opthdr = cursor;

    if (*nexthdr != NEXTHDR_HOP)
        return 0;

    if ((void *)(opthdr + 1) > data_end)
        return -1;

    *nexthdr = opthdr->nexthdr;
    *l4 = cursor + rs_cilium_ipv6_optlen(opthdr);
    return 0;
}

SEC("xdp")
int rs_cilium_ipv6_exthdr_l4_offset(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6;
    struct udphdr *checked_udp;
    struct udphdr *udp;
    void *fixed_l4;
    void *l4;
    __u8 nexthdr;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6)
        return XDP_PASS;

    ip6 = data + sizeof(*eth);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    nexthdr = ip6->nexthdr;
    fixed_l4 = (void *)(ip6 + 1);
    l4 = fixed_l4;

    if (rs_cilium_skip_hopopts(l4, data_end, &nexthdr, &l4) < 0)
        return XDP_PASS;
    if (nexthdr != NEXTHDR_UDP)
        return XDP_PASS;

    checked_udp = fixed_l4;
    if ((void *)(checked_udp + 1) > data_end)
        return XDP_PASS;

    udp = l4;
    return bpf_ntohs(udp->dest) == 53 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
