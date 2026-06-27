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

struct policy_state {
    __u32 drop_proto;
    __u32 seen_ipv4;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct policy_state);
} policy_map SEC(".maps");

SEC("tc")
int rs_actplane_policy_map_merge(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct policy_state *policy;
    __u32 key = 0;
    __u32 proto;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    proto = bpf_ntohs(eth->h_proto);
    policy = bpf_map_lookup_elem(&policy_map, &key);
    if (!policy)
        return TC_ACT_OK;

    if (proto == ETH_P_IP) {
        policy->seen_ipv4 += 1;
    }

    return policy->drop_proto == proto ? TC_ACT_SHOT : TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
