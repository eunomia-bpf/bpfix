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

struct config {
    __u32 slots[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} configs SEC(".maps");

SEC("xdp")
int map_value_index_guard_oob(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct config *cfg;
    __u32 key = 0;
    __u32 selector;
    __u32 slot;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    selector = bpf_ntohs(eth->h_proto) & 7;
    if (selector == 0) {
        slot = 0;
    } else if (selector == 2) {
        slot = 1;
    } else if (selector == 5) {
        slot = 2;
    } else {
        return XDP_PASS;
    }

    cfg = bpf_map_lookup_elem(&configs, &key);
    if (!cfg)
        return XDP_PASS;

    return cfg->slots[slot] ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
