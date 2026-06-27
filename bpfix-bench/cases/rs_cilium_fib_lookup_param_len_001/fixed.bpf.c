#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

SEC("xdp")
int rs_cilium_fib_lookup_param_len(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    struct bpf_fib_lookup fib = {};

    fib.family = AF_INET;
    fib.ipv4_src = iph->saddr;
    fib.ipv4_dst = iph->daddr;
    fib.ifindex = ctx->ingress_ifindex;

    long rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);

    if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
        __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
        return bpf_redirect(fib.ifindex, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
