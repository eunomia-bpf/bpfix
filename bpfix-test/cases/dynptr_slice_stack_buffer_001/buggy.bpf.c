#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif

extern int bpf_dynptr_from_xdp(struct xdp_md *x, __u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, __u32 offset, void *buffer__opt, __u32 buffer__szk) __ksym;

SEC("xdp")
int dynptr_slice_stack_buffer(struct xdp_md *ctx)
{
    struct bpf_dynptr ptr;
    __u64 scratch = 0;
    __u16 trailer = 0;
    void *bytes;
    void *tail;

    if (bpf_dynptr_from_xdp(ctx, 0, &ptr))
        return XDP_PASS;

    bytes = bpf_dynptr_slice(&ptr, 0, &scratch, 9);
    if (!bytes)
        return XDP_PASS;

    tail = bpf_dynptr_slice(&ptr, 12, &trailer, 3);
    if (!tail)
        return XDP_PASS;

    return ((__u8 *)tail)[0] == 0x08 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
