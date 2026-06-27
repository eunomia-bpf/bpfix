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

SEC("xdp")
int xdp_test(struct xdp_md *ctx)
{
    char *data = (char *)(long)ctx->data;
    char *data_end = (char *)(long)ctx->data_end;
    struct ethhdr *eth = (void *)data;
    struct iphdr *ip;
    char *address;
    __u32 off;
    __u8 byte;

    if ((void *)(eth + 1) > (void *)data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > (void *)data_end)
        return XDP_PASS;

    off = ip->ihl * 4;
    if (off < sizeof(*ip))
        return XDP_PASS;

    address = (char *)ip + off;
    if (address <= data || address > data_end)
        return XDP_PASS;

    byte = *address;
    bpf_printk("byte=%u\n", byte);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
