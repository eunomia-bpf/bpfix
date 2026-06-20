#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
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
    struct event *audit = bpf_ringbuf_reserve(&events, sizeof(*audit), 0);
    if (!audit)
        return XDP_PASS;
    audit->mark = 3;

    struct event *rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
    rec->mark = 7;
    bpf_ringbuf_submit(audit, 0);
    bpf_ringbuf_submit(rec, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
