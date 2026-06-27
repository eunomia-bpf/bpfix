#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

SEC("xdp")
int packet_option(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 off = ((__u64)bpf_get_prandom_u32()) << 32;
    void *ptr = data + off;

    if (ptr + 1 > data_end)
        return XDP_PASS;
    return *(__u8 *)ptr;
}

char _license[] SEC("license") = "GPL";
