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
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} sums SEC(".maps");

SEC("xdp")
int helper_csum_diff_stack_len(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 key = 0;
    __u32 ihl;
    __u32 payload_len;
    __u32 sum32;
    __s64 sum;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    ihl = iph->ihl << 2;
    if (ihl < sizeof(*iph))
        return XDP_PASS;
    if ((void *)iph + ihl > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;
    if (bpf_ntohs(iph->tot_len) < ihl)
        return XDP_PASS;

    payload_len = bpf_ntohs(iph->tot_len) - ihl;

    struct {
        __be32 saddr;
        __be32 daddr;
        __be32 proto_len;
    } pseudo = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .proto_len = bpf_htonl((IPPROTO_UDP << 16) | payload_len),
    };

    sum = bpf_csum_diff(0, 0, (__be32 *)&pseudo, sizeof(pseudo), 0);
    if (sum < 0)
        return XDP_PASS;

    sum32 = (__u32)sum;
    bpf_map_update_elem(&sums, &key, &sum32, BPF_ANY);
    return (sum32 & 0xffff) ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
