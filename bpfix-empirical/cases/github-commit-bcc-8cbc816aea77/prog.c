#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

struct session_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct session_leaf {
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct session_key);
    __type(value, struct session_leaf);
} sessions SEC(".maps");

SEC("tc")
int prog(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    if (ip->protocol != IPPROTO_TCP)
        return 0;

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    struct session_key key = {};
    struct session_leaf leaf;

    key.dst_ip = ip->daddr;
    key.src_ip = ip->saddr;
    key.dst_port = tcp->dest;
    key.src_port = tcp->source;

    leaf.timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&sessions, &key, &leaf, BPF_ANY);
    return -1;
}

char LICENSE[] SEC("license") = "GPL";
