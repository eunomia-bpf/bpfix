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

static __always_inline struct udphdr *parse_udp(void *data, void *data_end)
{
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return 0;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return 0;
    if (iph->protocol != IPPROTO_UDP)
        return 0;

    struct udphdr *udp = (void *)(iph + 1);
    if ((void *)(udp + 1) > data_end)
        return 0;
    return udp;
}

SEC("xdp")
int packet_inline_return_cookie(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct udphdr *udp = parse_udp(data, data_end);

    if (!udp)
        return XDP_PASS;

    __u64 cookie = (__u64)(long)udp;
    /* Perform scalar operations on the cookie if needed, but do not destroy pointer provenance.
       The original code used asm to shift the pointer, which the verifier rejects.
       We keep the cookie as a scalar for demonstration, but we must use the original
       verified pointer 'udp' for memory access. */
    
    /* If the intent was to use the cookie for something else, we can do scalar math on 'cookie'.
       However, for the final access, we must use a pointer that the verifier knows is valid.
       The original code cast cookie back to udp. We can do that, but we must ensure the verifier
       accepts it. The safest way is to just use the original 'udp' pointer which is already validated.
       If we must use the cookie, we can cast it back, but the verifier might complain if it thinks
       the pointer was modified. Since we didn't modify the pointer value in a way that changes its
       address (just shifted and shifted back, effectively a no-op in the original intent),
       we can simply use the original 'udp' pointer. */

    return bpf_ntohs(udp->dest) == 53 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
