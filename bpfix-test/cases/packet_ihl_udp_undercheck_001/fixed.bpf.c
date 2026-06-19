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

SEC("xdp")
int packet_ihl_udp_undercheck(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    void *udp;
    __u32 ihl;
    __u16 dport;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph) || ihl > 60)
        return XDP_PASS;

    udp = data + sizeof(*eth) + ihl;
    if (udp + 4 > data_end)
        return XDP_PASS;

    dport = *(__u16 *)(udp + 2);
    return bpf_ntohs(dport) == 53 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
