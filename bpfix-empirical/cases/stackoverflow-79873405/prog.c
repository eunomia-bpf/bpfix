#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/nfsd4_write")
int write_ops(struct pt_regs *ctx, void *rqstp, void *cstate)
{
    __u64 value = 0;

    bpf_probe_read_kernel(&value, sizeof(value), rqstp);
    bpf_printk("value %llu", value);
    return 0;
}

char _license[] SEC("license") = "GPL";
