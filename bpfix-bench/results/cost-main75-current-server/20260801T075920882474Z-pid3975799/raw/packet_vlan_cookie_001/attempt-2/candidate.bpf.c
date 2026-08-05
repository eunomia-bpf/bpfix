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
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

struct vlan_hdr_local {
    __be16 tci;
    __be16 proto;
};

SEC("xdp")
int packet_vlan_cookie(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *cursor;
    __u16 proto;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    cursor = eth + 1;
    proto = bpf_ntohs(eth->h_proto);
    if (proto == ETH_P_8021Q) {
        struct vlan_hdr_local *vlan = cursor;

        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        proto = bpf_ntohs(vlan->proto);
        cursor = vlan + 1;
    }

    if (proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = cursor;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(iph + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Instead of casting pointer to integer and doing arithmetic (which is prohibited on pointers),
    // we can just use the pointer directly if we want to access the struct.
    // The original code tried to create a "cookie" by masking the pointer, likely to simulate
    // some state or just to test verifier constraints.
    // Since the goal is to check tcp->dest == 443, we can just do that directly.
    // The "cookie" logic seems to be an obfuscation or a specific test case for pointer arithmetic restrictions.
    // To fix the verifier error "R3 pointer arithmetic with <<= operator prohibited", we must avoid
    // casting the packet pointer to an integer and performing bitwise operations on it.
    
    // We simply access the destination port directly from the validated tcp pointer.
    return bpf_ntohs(tcp->dest) == 443 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
