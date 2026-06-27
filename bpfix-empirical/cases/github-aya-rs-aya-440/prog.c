#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

SEC("xdp")
int prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data >= data_end)
        return XDP_PASS;

    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                 data, data_end - data);
}

char LICENSE[] SEC("license") = "GPL";
