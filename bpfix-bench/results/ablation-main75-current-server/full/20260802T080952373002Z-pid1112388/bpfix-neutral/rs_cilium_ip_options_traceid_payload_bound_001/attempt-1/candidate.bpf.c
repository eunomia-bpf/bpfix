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
        if (opt_type != CILIUM_TRACE_OPT) {
            opt += optlen;
            continue;
        }

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
