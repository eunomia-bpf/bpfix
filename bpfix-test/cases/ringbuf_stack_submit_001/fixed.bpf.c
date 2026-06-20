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
int ringbuf_stack_submit(struct xdp_md *ctx)
{
    struct event *audit;
    struct event *ev;

    audit = bpf_ringbuf_reserve(&events, sizeof(*audit), 0);
    if (!audit)
        return XDP_PASS;
    audit->mark = 3;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        bpf_ringbuf_discard(audit, 0);
        return XDP_PASS;
    }

    ev->mark = 7;
    if (ctx->data == 0)
        ev->mark = 11;

    bpf_ringbuf_submit(audit, 0);
    bpf_ringbuf_submit(ev, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
