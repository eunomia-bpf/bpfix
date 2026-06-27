#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

SEC("xdp")
int xdp_nat_inner2outer_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    volatile __u8 byte = *(__u8 *)(data + 17);

    if (byte)
        return XDP_PASS;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
