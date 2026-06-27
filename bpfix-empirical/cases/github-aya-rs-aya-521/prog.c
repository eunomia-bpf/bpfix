#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct loop_ctx {
    __u64 seen;
};

static long cb(__u32 i, void *data)
{
    struct loop_ctx *ctx = data;
    ctx->seen += i;
    return 0;
}

SEC("tc")
int prog(struct __sk_buff *skb)
{
    struct loop_ctx ctx = {};
    return bpf_loop(5, cb, &ctx, 0);
}

char LICENSE[] SEC("license") = "GPL";
