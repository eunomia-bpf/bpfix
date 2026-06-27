#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#define SAMPLE_BYTES 18

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

SEC("xdp")
int perf_event_packet_payload(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u16 proto;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    proto = bpf_ntohs(eth->h_proto);
    if (data + SAMPLE_BYTES > data_end)
        return XDP_PASS;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, SAMPLE_BYTES);
    return proto == ETH_P_IP ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
