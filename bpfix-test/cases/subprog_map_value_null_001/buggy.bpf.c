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
    __u32 seen_packets;
    __u32 pass_proto;
    __u32 key_xor;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct config);
} configs SEC(".maps");

static __noinline struct config *lookup_config(__u32 key)
{
    return bpf_map_lookup_elem(&configs, &key);
}

SEC("xdp")
int subprog_map_value_null(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct config *cfg;
    __u32 key;
    __u16 proto;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    proto = bpf_ntohs(eth->h_proto);
    key = eth->h_dest[5] & 1;
    cfg = lookup_config(key);
    cfg->seen_packets += 1;
    cfg->key_xor ^= key;
    if (cfg->drop_proto == proto)
        return XDP_DROP;
    if (cfg->pass_proto == proto)
        return XDP_PASS;
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
