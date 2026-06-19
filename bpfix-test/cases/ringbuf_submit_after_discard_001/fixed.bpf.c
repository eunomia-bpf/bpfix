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

struct event {
    __u32 mark;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("xdp")
int ringbuf_submit_after_discard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct event *rec;
    struct ethhdr *eth = data;
    __u32 mark;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
        mark = 7;
    else
        mark = 11;
    rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
    if (!rec)
        return XDP_PASS;

    rec->mark = mark;
    if (mark == 7) {
        bpf_ringbuf_discard(rec, 0);
        return XDP_DROP;
    }

    bpf_ringbuf_submit(rec, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
