#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
    bpf_trace_printk((const char *)0, 20);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
