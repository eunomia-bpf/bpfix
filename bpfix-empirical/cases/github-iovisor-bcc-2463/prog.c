#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

SEC("xdp")
int prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)(iph + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    __u32 udp_len = bpf_ntohs(udp->len) & 0x1ff;
    if (udp_len < sizeof(*udp))
        return XDP_DROP;

    udp->check = 0;
    __u64 sum = bpf_csum_diff(0, 0, (void *)udp, udp_len, 0);
    udp->check = (__u16)sum;
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
