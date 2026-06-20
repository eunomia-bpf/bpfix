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

SEC("xdp")
int xdp_adjust_tail_stale(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct udphdr *udp;
    __u32 ihl_bytes;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    if (bpf_xdp_adjust_tail(ctx, -4))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;
    ihl_bytes = (__u32)iph->ihl << 2;
    if (ihl_bytes < sizeof(*iph))
        return XDP_PASS;
    if ((void *)iph + ihl_bytes > data_end)
        return XDP_PASS;

    udp = (void *)iph + ihl_bytes;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    return bpf_ntohs(udp->dest) == 53 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
