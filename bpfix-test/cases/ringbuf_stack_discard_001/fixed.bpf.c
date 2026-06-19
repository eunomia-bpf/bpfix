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
int ringbuf_stack_discard(struct xdp_md *ctx)
{
    struct event *rec;

    rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
    if (!rec)
        return XDP_PASS;
    rec->mark = 7;
    bpf_ringbuf_discard(rec, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
