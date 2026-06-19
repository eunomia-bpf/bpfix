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
#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

SEC("xdp")
int xdp_adjust_head_stale(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, (int)sizeof(*eth)) < 0)
        return XDP_ABORTED;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    return iph->protocol == IPPROTO_UDP ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
