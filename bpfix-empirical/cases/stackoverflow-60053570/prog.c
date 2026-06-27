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
#ifndef XDP_TX
#define XDP_TX 3
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#define ICMP_ECHO_LEN 64

SEC("xdp")
int _xdp_icmp(struct xdp_md *xdp)
{
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct icmphdr *icmph;
    __s64 sum;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    icmph = (void *)(iph + 1);
    if ((void *)(icmph + 1) > data_end)
        return XDP_DROP;
    if (icmph->type != ICMP_ECHO)
        return XDP_PASS;

    icmph->type = 0;
    icmph->checksum = 0;
    sum = bpf_csum_diff(0, 0, (__be32 *)icmph, ICMP_ECHO_LEN, 0);
    icmph->checksum = ~((sum & 0xffff) + (sum >> 16));
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
