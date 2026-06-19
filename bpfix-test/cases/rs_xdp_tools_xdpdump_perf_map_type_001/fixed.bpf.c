#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xffffffffULL
#endif

#define MAX_CPUS 64
#define SNAPLEN 64

struct pkt_trace_metadata {
    __u32 prog_index;
    __u32 ifindex;
    __u32 rx_queue;
    __u16 pkt_len;
    __u16 cap_len;
    __u32 action;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, __u32);
    __type(value, __u32);
} xdpdump_perf_map SEC(".maps");

static __always_inline __u16 rs_min_u16(__u16 left, __u16 right)
{
    return left < right ? left : right;
}

SEC("xdp")
int rs_xdp_tools_xdpdump_perf_map_type(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct pkt_trace_metadata metadata = {};
    __u16 pkt_len;
    __u64 flags;

    if (data >= data_end)
        return XDP_PASS;

    pkt_len = (__u16)(data_end - data);
    metadata.prog_index = 7;
    metadata.ifindex = ctx->ingress_ifindex;
    metadata.rx_queue = ctx->rx_queue_index;
    metadata.pkt_len = pkt_len;
    metadata.cap_len = rs_min_u16(pkt_len, SNAPLEN);
    metadata.action = XDP_PASS;
    metadata.flags = 0;

    flags = ((__u64)metadata.cap_len << 32) | BPF_F_CURRENT_CPU;
    bpf_perf_event_output(ctx, &xdpdump_perf_map, flags,
                          &metadata, sizeof(metadata));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
