#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#define MAX_SOCKS 4

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, MAX_SOCKS);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

static __u32 rr;

SEC("xdp")
int rs_xdp_tools_xdpsock_redirect_map_type(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 1 > data_end)
        return XDP_PASS;
    if (*(__u8 *)data == 0xff)
        return XDP_PASS;

    rr = (rr + 1) & (MAX_SOCKS - 1);
    return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
