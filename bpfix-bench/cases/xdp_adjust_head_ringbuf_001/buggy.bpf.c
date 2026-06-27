#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

struct event {
    __u32 mark;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("xdp")
int xdp_adjust_head_ringbuf(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    struct event *rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
    if (!rec)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, (int)sizeof(*eth)) < 0) {
        bpf_ringbuf_discard(rec, 0);
        return XDP_ABORTED;
    }

    rec->mark = 7;
    bpf_ringbuf_submit(rec, 0);

    return iph->protocol == IPPROTO_UDP ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
