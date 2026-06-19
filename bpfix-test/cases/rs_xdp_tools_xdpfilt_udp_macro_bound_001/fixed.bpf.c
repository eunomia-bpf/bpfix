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
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct hdr_cursor {
    void *pos;
};

#define CHECK_RET(ret)                 \
    do {                               \
        if ((ret) < 0)                 \
            return XDP_PASS;           \
    } while (0)

#define DROP_DNS_UDP(udp)                              \
    do {                                               \
        if ((udp)->dest == bpf_htons(53))              \
            return XDP_DROP;                           \
    } while (0)

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;

    if ((void *)(eth + 1) > data_end)
        return -1;

    nh->pos = eth + 1;
    *ethhdr = eth;
    return eth->h_proto;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh, void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if ((void *)(iph + 1) > data_end)
        return -1;

    hdrsize = iph->ihl * 4;
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;
    return iph->protocol;
}

SEC("xdp")
int rs_xdp_tools_xdpfilt_udp_macro_bound(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = { .pos = data };
    struct ethhdr *eth;
    struct iphdr *iph;
    struct udphdr *udp;
    int eth_type;
    int ip_type;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    CHECK_RET(eth_type);
    if (eth_type != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip_type = parse_iphdr(&nh, data_end, &iph);
    CHECK_RET(ip_type);
    if (ip_type != IPPROTO_UDP)
        return XDP_PASS;

    udp = nh.pos;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    DROP_DNS_UDP(udp);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
