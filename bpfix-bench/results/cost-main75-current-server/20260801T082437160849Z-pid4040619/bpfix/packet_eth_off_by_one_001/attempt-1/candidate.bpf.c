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
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

SEC("xdp")
int packet_eth_off_by_one(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u16 proto;
    __u8 nexthdr;

    if (data + 14 > data_end)
        return XDP_PASS;

    proto = *(__u16 *)(data + 12);
    if (bpf_ntohs(proto) == ETH_P_IP)
        return XDP_DROP;
    if (bpf_ntohs(proto) != ETH_P_IPV6)
        return XDP_PASS;

    if (data + 21 > data_end)
        return XDP_PASS;
    nexthdr = *(__u8 *)(data + 20);
    return nexthdr == IPPROTO_UDP ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
