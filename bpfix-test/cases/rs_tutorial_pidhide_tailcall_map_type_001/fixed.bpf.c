// SPDX-License-Identifier: BSD-3-Clause
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#define PROG_01 1

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");

SEC("xdp")
int entry_tailcall_dispatch(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 1 > data_end)
        return XDP_PASS;
    if (*(__u8 *)data == 0xaa)
        bpf_tail_call(ctx, &map_prog_array, PROG_01);
    return XDP_PASS;
}

SEC("xdp")
int tail_target_drop(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char _license[] SEC("license") = "Dual BSD/GPL";
