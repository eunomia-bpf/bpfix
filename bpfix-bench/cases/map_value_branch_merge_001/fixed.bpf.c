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
    __u32 seen_udp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct config);
} configs SEC(".maps");

SEC("xdp")
int map_value_branch_merge(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u8 proto;
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&configs, &key);
    struct config *override;

    if (!cfg)
        return XDP_PASS;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    proto = iph->protocol;

    if (proto == IPPROTO_UDP) {
        key = IPPROTO_UDP;
        override = bpf_map_lookup_elem(&configs, &key);
        if (override)
            cfg = override;
        cfg->seen_udp = 1;
    } else if (proto == IPPROTO_TCP) {
        cfg->seen_udp = 0;
    }

    return cfg->drop_proto == proto ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
