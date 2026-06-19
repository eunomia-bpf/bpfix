#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#define PROBE_BYTES 10

SEC("xdp")
int rs_xdp_tools_load_bytes_stack_len(struct xdp_md *ctx)
{
    __u8 buf[PROBE_BYTES];
    int err;

    err = bpf_xdp_load_bytes(ctx, 0, buf, PROBE_BYTES);
    if (err)
        return XDP_ABORTED;

    if (buf[0] == 'B' && buf[9] == 'X')
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
