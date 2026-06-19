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

extern int bpf_dynptr_from_xdp(struct xdp_md *x, __u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, __u32 offset, void *buffer__opt, __u32 buffer__szk) __ksym;

SEC("xdp")
int dynptr_slice_missing_null_check(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct bpf_dynptr ptr;
    struct ethhdr *eth;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (bpf_dynptr_from_xdp(ctx, 0, &ptr))
        return XDP_PASS;

    eth = bpf_dynptr_slice(&ptr, 0, 0, sizeof(*eth));
    if (!eth)
        return XDP_PASS;

    return bpf_ntohs(eth->h_proto) == ETH_P_IP ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
