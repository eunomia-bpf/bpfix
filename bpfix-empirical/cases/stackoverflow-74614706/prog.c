#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

static __noinline int parse_outer(__u32 seed)
{
    volatile char buf[288];

    buf[0] = 1;
    buf[287] = 2;
    return buf[seed & 1 ? 0 : 287];
}

static __noinline int parse_inner(__u32 seed)
{
    volatile char buf[288];

    buf[0] = 3;
    buf[287] = 4;
    return parse_outer(seed) + buf[seed & 1 ? 287 : 0];
}

SEC("xdp")
int prog_xdp_ingress(struct xdp_md *ctx)
{
    return parse_inner(ctx->rx_queue_index) ? XDP_PASS : XDP_DROP;
}

char _license[] SEC("license") = "GPL";
