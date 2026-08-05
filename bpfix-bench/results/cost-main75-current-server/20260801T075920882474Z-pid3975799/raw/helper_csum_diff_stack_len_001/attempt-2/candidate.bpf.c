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
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} sums SEC(".maps");

SEC("xdp")
int helper_csum_diff_stack_len(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 ihl;
    __u32 payload_len;
    __s64 sum;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    ihl = iph->ihl << 2;
    if (ihl < sizeof(*iph))
        return XDP_PASS;
    if ((void *)iph + ihl > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;
    if (bpf_ntohs(iph->tot_len) < ihl)
        return XDP_PASS;

    payload_len = bpf_ntohs(iph->tot_len) - ihl;

    __u64 pseudo = ((__u64)iph->saddr << 32) | iph->daddr;

    // Use bpf_csum_diff directly with packet pointers or valid stack pointers.
    // The previous error was "invalid read from stack R3 off=-8 size=12".
    // bpf_csum_diff expects pointers to be valid.
    // We can compute the pseudo-header checksum by passing the source and dest addresses
    // directly if we structure the call correctly, but bpf_csum_diff takes pointers.
    // A safer way is to ensure the stack pointer is properly aligned and accessible.
    // However, the simplest fix for verifier issues with stack pointers in csum_diff
    // is often to avoid stack pointers for the 'from'/'to' buffers if possible,
    // or ensure the verifier knows the stack slot is valid.
    //
    // Actually, the issue is that bpf_csum_diff requires the pointers to be
    // either packet pointers or valid stack pointers. The verifier rejected
    // the stack pointer because it might not have tracked it as a valid read
    // source for this helper in this specific context/version, or due to alignment/size.
    //
    // Let's try passing the addresses directly into the csum_diff by constructing
    // the pseudo-header in a way the verifier accepts.
    // Alternatively, we can just use bpf_csum_diff on the packet data itself if we
    // were checksumming the packet, but here we are doing pseudo-header.
    //
    // The standard way to do pseudo-header checksum in eBPF without stack issues
    // is to use bpf_csum_diff with the packet pointers for saddr and daddr.
    // saddr is at iph + 12, daddr is at iph + 16.
    // We can pass them as two separate 4-byte chunks.
    
    // Calculate pseudo header checksum:
    // sum = csum_diff(0, 0, &saddr, 4, 0) + csum_diff(0, 0, &daddr, 4, 0) + csum_diff(0, 0, &len_proto, 4, 0)
    // But bpf_csum_diff only takes one 'from' pointer.
    //
    // Let's stick to the stack approach but ensure the stack variable is used correctly.
    // The error "invalid read from stack" suggests the verifier didn't like the pointer.
    // In newer kernels, stack pointers are allowed. In older ones, they might not be.
    //
    // A robust workaround is to use bpf_csum_diff on the packet data for the addresses.
    // We can do:
    // sum = bpf_csum_diff(0, 0, (void *)(long)(iph + 12), 4, 0); // saddr
    // sum = bpf_csum_diff(0, 0, (void *)(long)(iph + 16), 4, sum); // daddr
    // Then add protocol and length.
    
    __u32 proto_len = (__u32)iph->protocol << 16 | (__u32)bpf_ntohs(iph->tot_len);
    
    // Start with 0
    sum = 0;
    
    // Add saddr (4 bytes)
    sum = bpf_csum_diff(0, 0, (void *)(long)(iph + 12), 4, sum);
    if (sum < 0)
        return XDP_PASS;
        
    // Add daddr (4 bytes)
    sum = bpf_csum_diff(0, 0, (void *)(long)(iph + 16), 4, sum);
    if (sum < 0)
        return XDP_PASS;
        
    // Add protocol and length (4 bytes)
    // We need to put proto_len on stack or pass a pointer to it.
    // Let's put it on stack.
    __u32 stack_proto_len;
    __builtin_memcpy(&stack_proto_len, &proto_len, sizeof(proto_len));
    
    sum = bpf_csum_diff(0, 0, &stack_proto_len, 4, sum);
    if (sum < 0)
        return XDP_PASS;

    __u32 key = 0;
    __u32 sum32 = (__u32)sum;
    bpf_map_update_elem(&sums, &key, &sum32, BPF_ANY);
    return (sum32 & 0xffff) ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
