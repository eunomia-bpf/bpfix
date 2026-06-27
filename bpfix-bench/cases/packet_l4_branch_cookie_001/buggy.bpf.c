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
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

SEC("xdp")
int packet_l4_branch_cookie(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *l4 = 0;
    __u8 proto;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    proto = iph->protocol;
    if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);

        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        l4 = udp;
    } else if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);

        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        l4 = tcp;
    } else {
        return XDP_PASS;
    }

    __u64 cookie = (__u64)(long)l4;
    asm volatile("%[cookie] <<= 32; %[cookie] >>= 32" : [cookie] "+r"(cookie));
    l4 = (void *)(long)cookie;

    if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;

        return bpf_ntohs(udp->dest) == 53 ? XDP_DROP : XDP_PASS;
    }

    struct tcphdr *tcp = l4;
    return bpf_ntohs(tcp->dest) == 443 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
