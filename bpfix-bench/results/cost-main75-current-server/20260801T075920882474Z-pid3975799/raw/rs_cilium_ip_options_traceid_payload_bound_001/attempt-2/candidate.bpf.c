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

#define CILIUM_TRACE_OPT 0x9e
#define IPOPT_END 0
#define IPOPT_NOOP 1
#define OPT16_LEN 4
#define OPT32_LEN 6
#define OPT64_LEN 10
#define MAX_IPV4_OPTS 3
#define IHL_WITH_NO_OPTS 5

static __always_inline int rs_load_trace_id(void *opt, void *data_end, __u8 optlen,
                                            __s64 *value)
{
    if (optlen == OPT16_LEN) {
        __be16 *raw = opt + 2;

        if ((void *)(raw + 1) > data_end)
            return -1;
        *value = bpf_ntohs(*raw);
        return 0;
    }

    if (optlen == OPT32_LEN) {
        __be32 *raw = opt + 2;

        if ((void *)(raw + 1) > data_end)
            return -1;
        *value = bpf_ntohl(*raw);
        return 0;
    }

    if (optlen == OPT64_LEN) {
        __be64 *raw = opt + 2;

        if ((void *)(raw + 1) > data_end)
            return -1;
        *value = __builtin_bswap64(*raw);
        return 0;
    }

    return -2;
}

static __always_inline int rs_trace_id_from_ip4(void *data, void *data_end,
                                                struct iphdr *ip4, __s64 *value)
{
    void *opt = (void *)(ip4 + 1);
    void *end = data + sizeof(struct ethhdr) + ((__u32)ip4->ihl << 2);
    __u8 opt_type;
    __u8 optlen;
    int i;

    if (ip4->ihl <= IHL_WITH_NO_OPTS)
        return 0;

#pragma unroll(MAX_IPV4_OPTS)
    for (i = 0; i < MAX_IPV4_OPTS && opt < end; i++) {
        if (opt + 1 > data_end)
            return -1;

        opt_type = *(__u8 *)opt;
        if (opt_type == IPOPT_END)
            break;

        if (opt_type == IPOPT_NOOP) {
            opt++;
            continue;
        }

        if (opt + 2 > data_end)
            return -1;

        optlen = *(__u8 *)(opt + 1);
        
        /* Validate that the option length is reasonable and fits within packet bounds */
        if (optlen < 2 || opt + optlen > data_end)
            return -1;

        if (opt_type != CILIUM_TRACE_OPT) {
            opt += optlen;
            continue;
        }

        /* 
         * The verifier fails because it cannot prove that 'opt' (which is used as base for rs_load_trace_id)
         * is still within bounds after the loop updates, due to pointer provenance issues when adding scalars.
         * We explicitly re-check bounds for the specific access inside rs_load_trace_id by passing 'opt' 
         * and ensuring the helper checks against data_end.
         * However, the previous failure was specifically about R3/R4 offset being outside packet.
         * The issue is that 'opt' is a void* derived from ip4+1. When we do opt += optlen, the verifier 
         * loses track of the exact offset relative to data_end in some paths or considers the pointer 
         * invalid for direct dereference if not carefully bounded.
         * 
         * To fix this robustly, we ensure that before calling rs_load_trace_id, we verify that the 
         * specific memory region we are about to read (opt + 2 + size) is within data_end.
         * rs_load_trace_id already does this check, but the verifier might reject the call if the 
         * pointer 'opt' itself is considered out of bounds or unbounded.
         * 
         * Let's ensure 'opt' is valid for reading the header (type + len) which we already did.
         * The crash happened at rs_load_trace_id accessing opt+2.
         * We need to make sure the verifier knows opt+2 is safe.
         * Since we checked opt + optlen <= data_end, and optlen >= 2, opt+2 <= data_end is implied.
         * But the verifier might not propagate this implication through the function call boundary 
         * if the pointer 'opt' has lost its "pkt" context or if the offset calculation is complex.
         * 
         * A common fix is to pass the pointer and let the helper do the check, which we do.
         * The previous error "R3 offset is outside of the packet" suggests the verifier thought 
         * the pointer passed to rs_load_trace_id was invalid.
         * 
         * Let's try to inline the check or ensure the pointer is refreshed.
         * Actually, the previous attempt added `if (optlen < 2 || opt + optlen > data_end) return -1;`.
         * This should have been sufficient. Why did it fail?
         * In the log: `invalid access to packet, off=36 size=2, R3(id=0,off=36,r=36)`.
         * R3 was `opt + 2`. `opt` was at offset 34. `opt+2` is 36.
         * The check `opt + optlen > data_end` was performed.
         * If optlen=4, opt+4 <= data_end. Then opt+2 <= data_end.
         * 
         * Perhaps the issue is that `opt` is a `void*` and the verifier is strict about 
         * pointer arithmetic on `void*` in some contexts or the specific version of the verifier.
         * Let's try to use a `char*` or `__u8*` for the pointer arithmetic to help the verifier 
         * track offsets more precisely, or simply ensure the bounds check is done on the 
         * specific pointer used for access.
         */

        return rs_load_trace_id(opt, data_end, optlen, value);
    }

    return 0;
}

SEC("xdp")
int rs_cilium_ip_options_traceid_payload_bound(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip4;
    __s64 trace_id = 0;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    ip4 = data + sizeof(*eth);
    if ((void *)(ip4 + 1) > data_end)
        return XDP_PASS;
    if (ip4->protocol != IPPROTO_UDP)
        return XDP_PASS;

    if (rs_trace_id_from_ip4(data, data_end, ip4, &trace_id) < 0)
        return XDP_PASS;

    return trace_id == 0x1234 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
