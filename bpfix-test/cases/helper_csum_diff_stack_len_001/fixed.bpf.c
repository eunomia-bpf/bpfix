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
int helper_csum_diff_stack_len(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u64 seed = 0x0102030405060708ULL;
    __s64 sum;

    sum = bpf_csum_diff(0, 0, (__be32 *)&seed, sizeof(seed), 0);
    if (sum < 0)
        return XDP_PASS;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    return bpf_ntohs(eth->h_proto) == ETH_P_IP ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
