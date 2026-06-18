// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
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
#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP 2
#endif

#define CILIUM_MCAST_MAX_GREC 4
#define IGMPV3_CHANGE_TO_EXCLUDE 4
#define CILIUM_MDNS_GROUP 0xe00000fbU

struct cilium_igmpv3_report {
    __u8 type;
    __u8 resv1;
    __be16 csum;
    __be16 resv2;
    __be16 ngrec;
};

struct cilium_igmpv3_grec {
    __u8 grec_type;
    __u8 grec_auxwords;
    __be16 grec_nsrcs;
    __be32 grec_mca;
};

static __always_inline bool cilium_mcast_ipv4_is_igmp(const struct iphdr *ip4)
{
    return ip4->protocol == IPPROTO_IGMP;
}

SEC("xdp")
int cilium_mcast_igmpv3_grec_bound(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip4;
    const struct cilium_igmpv3_report *rep;
    const struct cilium_igmpv3_grec *rec;
    __u32 ip_len;
    __u16 ngrec;
    __u32 i;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    ip4 = (struct iphdr *)(eth + 1);
    if ((void *)(ip4 + 1) > data_end)
        return XDP_PASS;
    if (!cilium_mcast_ipv4_is_igmp(ip4))
        return XDP_PASS;

    ip_len = (__u32)ip4->ihl << 2;
    if (ip_len < sizeof(*ip4))
        return XDP_PASS;
    if ((void *)ip4 + ip_len + sizeof(*rep) > data_end)
        return XDP_PASS;

    rep = (const struct cilium_igmpv3_report *)((__u8 *)ip4 + ip_len);
    ngrec = bpf_ntohs(rep->ngrec);
    if (ngrec > CILIUM_MCAST_MAX_GREC)
        return XDP_PASS;

#pragma unroll
    for (i = 0; i < CILIUM_MCAST_MAX_GREC; i++) {
        if (i < ngrec) {
            rec = (const struct cilium_igmpv3_grec *)((const __u8 *)(rep + 1) + i * sizeof(*rec));
            if (rec->grec_type == IGMPV3_CHANGE_TO_EXCLUDE &&
                rec->grec_mca == bpf_htonl(CILIUM_MDNS_GROUP))
                return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
