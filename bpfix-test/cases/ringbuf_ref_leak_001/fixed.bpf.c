#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif

struct event {
    __u32 mark;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("xdp")
int ringbuf_ref_leak(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    bool drop_branch = false;
    struct event *rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);

    if (data + 1 <= data_end && *(__u8 *)data == 0)
        drop_branch = true;

    if (!rec)
        return XDP_PASS;

    rec->mark = 7;
    if (drop_branch) {
        bpf_ringbuf_discard(rec, 0);
        return XDP_DROP;
    }

    bpf_ringbuf_submit(rec, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
