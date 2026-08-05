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

    // The original code attempted to mask the pointer using shifts on a pointer-typed register,
    // which is prohibited by the verifier ("R3 pointer arithmetic with <<= operator prohibited").
    // To fix this, we must perform the arithmetic on a scalar integer type (__u64) and then
    // cast back to a pointer. The verifier allows casting a scalar to a pointer if the scalar
    // is derived from a valid packet pointer and the arithmetic is safe.
    // However, simply masking a packet pointer to get a "cookie" and then using it as a pointer
    // to access memory is dangerous and often rejected if the verifier cannot prove the resulting
    // pointer is within bounds.
    //
    // The intent of the original code seems to be to use the lower 32 bits of the UDP header pointer
    // as a "cookie" (perhaps for identification or logging in a more complex scenario), but then
    // it casts it back to a pointer to access `udp->dest`.
    //
    // Since `udp` is already a valid pointer to the UDP header (verified by parse_udp),
    // we can simply use `udp` directly. The "cookie" manipulation appears to be a red herring
    // or a bug in the original logic that caused the verifier failure.
    //
    // If the goal is strictly to fix the verifier error while preserving the *packet inspection*
    // semantics (checking if dest port is 53), we can just use the `udp` pointer directly.
    // The shift/mask operation on the pointer itself is what causes the rejection.
    //
    // Let's assume the "cookie" logic was intended to demonstrate pointer arithmetic safety.
    // We can achieve a similar "scalarization" by casting to __u64, doing the math, and casting back,
    // BUT the verifier will still reject using that new pointer for memory access unless it can
    // prove it's within [data, data_end]. Since the mask `<<= 32; >>= 32` effectively keeps the
    // lower 32 bits, on a 64-bit system this changes the pointer value significantly (zeroing upper bits),
    // making it likely invalid for packet access.
    //
    // Given the context of "fixing verifier failures", the most robust fix that preserves the
    // intended packet processing (drop UDP port 53) is to remove the invalid pointer arithmetic
    // and use the valid `udp` pointer directly.

    return bpf_ntohs(udp->dest) == 53 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
