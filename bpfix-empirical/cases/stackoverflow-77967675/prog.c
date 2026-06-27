#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

struct loop_ctx {
    void *data;
    void *data_end;
};

static long check_byte(__u32 index, void *data)
{
    struct loop_ctx *ctx = data;
    __u8 *pkt = ctx->data;
    __u8 value = pkt[index];

    if (value == 0xff)
        return 1;
    return 0;
}

SEC("xdp")
int packet_loop(struct xdp_md *ctx)
{
    struct loop_ctx loop = {
        .data = (void *)(long)ctx->data,
        .data_end = (void *)(long)ctx->data_end,
    };

    bpf_loop(100, check_byte, &loop, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
