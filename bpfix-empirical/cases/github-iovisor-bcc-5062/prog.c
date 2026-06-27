#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 74 > data_end)
        return XDP_DROP;

    __u64 cur = ctx->rx_queue_index & 63;
    if (cur < 2 || cur > 34)
        return XDP_PASS;

    void *checked = data + 34 + cur + 26;
    if (checked > data_end)
        return XDP_PASS;

    __u64 cur2 = cur;
    asm volatile("" : "+r"(cur2));
    void *unchecked = data + 34 + cur2;
    __u16 old = *(__u16 *)(unchecked + 24);
    return old ? XDP_TX : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
