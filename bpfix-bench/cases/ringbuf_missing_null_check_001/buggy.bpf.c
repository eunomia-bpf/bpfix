#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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
int ringbuf_missing_null(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    struct event *audit = bpf_ringbuf_reserve(&events, sizeof(*audit), 0);
    if (!audit)
        return XDP_PASS;
    audit->mark = 3;

    struct event *rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
    rec->mark = 7;
    __u16 proto = *(__u16 *)(data + 12);
    struct event *tail = bpf_ringbuf_reserve(&events, sizeof(*tail), 0);
    if (bpf_ntohs(proto) == ETH_P_IP)
        tail->mark = 11;
    else
        tail->mark = 13;
    bpf_ringbuf_submit(audit, 0);
    bpf_ringbuf_submit(rec, 0);
    bpf_ringbuf_submit(tail, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
