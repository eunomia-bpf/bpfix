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

#define REQUIRE_BYTES(ptr, bytes) \
    do { \
        if ((void *)(ptr) + (bytes) > data_end) \
            return XDP_PASS; \
    } while (0)

SEC("xdp")
int packet_macro_payload_undercheck(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct udphdr *udp;
    __u32 ihl;
    __u16 check;

    REQUIRE_BYTES(eth, sizeof(*eth));
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    iph = data + sizeof(*eth);
    REQUIRE_BYTES(iph, sizeof(*iph));
    ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph))
        return XDP_PASS;
    REQUIRE_BYTES(iph, ihl);
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    udp = (void *)iph + ihl;
    REQUIRE_BYTES(udp, sizeof(*udp));

    check = udp->check;
    return bpf_ntohs(check) == 0xBEEF ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
