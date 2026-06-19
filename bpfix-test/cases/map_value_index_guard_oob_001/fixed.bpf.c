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
    __u32 slots[2];
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
    __u32 idx;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    idx = bpf_ntohs(eth->h_proto) & 3;
    if (idx >= 2)
        return XDP_PASS;

    cfg = bpf_map_lookup_elem(&configs, &key);
    if (!cfg)
        return XDP_PASS;

    return cfg->slots[idx] ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
