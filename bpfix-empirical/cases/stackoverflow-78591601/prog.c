#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#define MAX_ARRAY_LEN 100

struct fragment_packet {
    __u32 payload[MAX_ARRAY_LEN];
};

SEC("xdp")
int aggr_handler_tail(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct fragment_packet *pkt = data;
    __u32 sample;

    if (data + 74 > data_end)
        return XDP_PASS;

    sample = pkt->payload[18];
    bpf_printk("AGGREGATE: %u\n", sample);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
