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

struct config {
    __u32 slots[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} configs SEC(".maps");

SEC("xdp")
int map_value_signed_index(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct config *cfg;
    __s32 idx;
    __u32 key = 0;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    idx = (__s8)eth->h_dest[5];
    if (idx < -1 || idx > 1)
        return XDP_PASS;

    cfg = bpf_map_lookup_elem(&configs, &key);
    if (!cfg)
        return XDP_PASS;

    return cfg->slots[idx] ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
