#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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
int ringbuf_branch_cookie(struct xdp_md *ctx)
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

    __u32 mark;
    if (iph->protocol == IPPROTO_UDP) {
        mark = 7;
    } else if (iph->protocol == IPPROTO_TCP) {
        mark = 11;
    } else {
        return XDP_PASS;
    }

    struct event *rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
    if (!rec)
        return XDP_PASS;

    rec->mark = mark;
    __u64 cookie = (__u64)(long)rec;
    struct event *shadow = (void *)(long)cookie;
    bpf_ringbuf_submit(shadow, 0);

    return mark == 7 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
