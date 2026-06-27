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
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define DNS_PORT 53
#define MAX_DOMAIN_SIZE 254

struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

struct domain_key {
    char name[MAX_DOMAIN_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct domain_key);
    __type(value, __u8);
} domain_denylist SEC(".maps");

SEC("xdp")
int xdp_dns(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    struct dnshdr *dns;
    char *qname;
    __u32 ihl;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return XDP_PASS;

    udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(DNS_PORT))
        return XDP_PASS;

    dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;
    if (dns->qdcount != bpf_htons(1))
        return XDP_PASS;

    qname = (char *)(dns + 1);
    if (qname + 1 > (char *)data_end)
        return XDP_PASS;

    if (bpf_map_lookup_elem(&domain_denylist, qname))
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
