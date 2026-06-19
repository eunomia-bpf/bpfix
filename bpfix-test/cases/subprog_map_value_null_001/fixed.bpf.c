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
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

struct config {
    __u32 drop_proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} configs SEC(".maps");

static __noinline struct config *lookup_config(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&configs, &key);
}

SEC("xdp")
int subprog_map_value_null(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct config *cfg;
    __u16 proto;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    proto = bpf_ntohs(eth->h_proto);
    cfg = lookup_config();
    if (!cfg)
        return XDP_PASS;

    return cfg->drop_proto == proto ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
