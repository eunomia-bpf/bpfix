#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
    const char *fmt = (const char *)(long)0;

    bpf_trace_printk(fmt, 20);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
