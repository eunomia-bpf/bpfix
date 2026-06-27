#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define XDPFILT_REQUIRE_ROOM(ptr, bytes) \
    do { \
        if ((void *)(ptr) + (bytes) > data_end) \
            return XDP_PASS; \
    } while (0)

static __always_inline int rs_xdp_tools_dport_policy(struct udphdr *udp)
{
    return bpf_ntohs(udp->dest) == 53 ? XDP_DROP : XDP_PASS;
}

SEC("xdp")
int rs_xdp_tools_ihl_macro_wrong_base(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct udphdr *udp;
    void *checked_l4;
    void *actual_l4;

    XDPFILT_REQUIRE_ROOM(eth, sizeof(*eth));
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    iph = data + sizeof(*eth);
    XDPFILT_REQUIRE_ROOM(iph, sizeof(*iph));
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    checked_l4 = (void *)(iph + 1);
    actual_l4 = (void *)iph + ((__u32)iph->ihl << 2);
    XDPFILT_REQUIRE_ROOM(checked_l4, sizeof(*udp));

    udp = actual_l4;
    return rs_xdp_tools_dport_policy(udp);
}

char _license[] SEC("license") = "GPL";
