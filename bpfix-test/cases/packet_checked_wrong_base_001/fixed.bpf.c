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
int packet_checked_wrong_base(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u16 proto;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    proto = eth->h_proto;
    return bpf_ntohs(proto) == ETH_P_IP ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
