#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

static int add_one(int x)
{
    return x + 1;
}

SEC("xdp")
int prog(struct xdp_md *ctx)
{
    return (add_one(ctx->rx_queue_index) & 1) ? XDP_PASS : XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
