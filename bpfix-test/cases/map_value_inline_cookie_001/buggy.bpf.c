#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct config {
    __u32 drop_proto;
    __u32 seen_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} configs SEC(".maps");

static __always_inline struct config *lookup_config(__u8 protocol)
{
    __u32 key = protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP ? 0 : 0;
    return bpf_map_lookup_elem(&configs, &key);
}

SEC("xdp")
int map_value_inline_cookie(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u8 proto = iph->protocol;
    struct config *cfg = lookup_config(proto);
    if (!cfg)
        return XDP_PASS;

    cfg->seen_packets += 1;

    __u64 cookie = (__u64)(long)cfg;
    asm volatile("%[cookie] <<= 32; %[cookie] >>= 32" : [cookie] "+r"(cookie));
    cfg = (struct config *)(long)cookie;

    return cfg->drop_proto == proto ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
