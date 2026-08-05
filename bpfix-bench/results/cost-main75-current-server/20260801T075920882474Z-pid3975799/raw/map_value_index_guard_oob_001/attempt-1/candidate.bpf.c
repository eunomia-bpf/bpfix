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
    __uint(type, BPF_MAP_TYPE_ARRAY);
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

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    selector = bpf_ntohs(eth->h_proto) & 7;
    if (selector != 0 && selector != 2 && selector != 5)
        return XDP_PASS;

    cfg = bpf_map_lookup_elem(&configs, &key);
    if (!cfg)
        return XDP_PASS;

    /*
     * The verifier rejects the original code because 'selector' can be 5,
     * which is out of bounds for slots[3] (indices 0, 1, 2).
     * We must ensure the index is within bounds before accessing the array.
     */
    if (selector >= 3)
        return XDP_PASS;

    return cfg->slots[selector] ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
