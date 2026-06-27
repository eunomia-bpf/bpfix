#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(struct xdp_md *ctx)
{
    char buf[64] = {};
    __u32 record_len = (__u32)(ctx->data_end - ctx->data);

    buf[record_len] = 1;
    return buf[0];
}

char LICENSE[] SEC("license") = "GPL";
