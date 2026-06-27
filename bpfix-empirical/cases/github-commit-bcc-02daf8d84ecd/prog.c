#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/blk_mq_end_request")
int prog(struct pt_regs *ctx)
{
    struct request *rq = (struct request *)PT_REGS_PARM1(ctx);
    __u64 sector = rq->__sector;
    __u32 len = rq->__data_len;

    return sector + len;
}

char LICENSE[] SEC("license") = "GPL";
