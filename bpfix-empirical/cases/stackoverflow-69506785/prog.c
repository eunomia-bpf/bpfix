#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/tcp_v4_rcv")
int bpf_prog(struct pt_regs *ctx, struct sk_buff *skb)
{
    __u16 dest = 0;

    bpf_probe_read_kernel(&dest, sizeof(dest), &skb->len);
    bpf_printk("dest %u", dest);
    return 0;
}

char _license[] SEC("license") = "GPL";
