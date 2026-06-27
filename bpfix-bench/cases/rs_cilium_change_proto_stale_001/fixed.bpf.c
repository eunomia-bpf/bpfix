#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

SEC("tc")
int rs_cilium_change_proto_stale(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6 = (void *)(eth + 1);

    if ((void *)(ip6 + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;
    if (ip6->version != 6 || ip6->nexthdr != IPPROTO_UDP)
        return TC_ACT_OK;

    if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0))
        return TC_ACT_OK;

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    eth->h_proto = bpf_htons(ETH_P_IP);
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
