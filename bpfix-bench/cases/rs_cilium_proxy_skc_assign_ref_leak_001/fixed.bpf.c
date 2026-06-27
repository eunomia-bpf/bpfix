// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define BPF_F_CURRENT_NETNS ((__u64)-1)
#define PROXY_MARK 7
#define PROXY_PORT 15001

SEC("tc")
int rs_cilium_proxy_skc_assign_ref_leak(struct __sk_buff *skb)
{
    struct bpf_sock_tuple tuple = {};
    struct bpf_sock *sk;
    long result;

    tuple.ipv4.saddr = bpf_htonl(0x0a000001);
    tuple.ipv4.daddr = bpf_htonl(0x0a000002);
    tuple.ipv4.sport = bpf_htons(10000);
    tuple.ipv4.dport = bpf_htons(PROXY_PORT);

    sk = bpf_skc_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    if (!sk)
        return TC_ACT_OK;

    result = bpf_sk_assign(skb, sk, 0);
    bpf_sk_release(sk);

    if (result == 0 && skb->mark == PROXY_MARK)
        return TC_ACT_SHOT;

    return result == 0 ? TC_ACT_SHOT : TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
