#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("raw_tracepoint/sched_wakeup")
int trace_sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    __u32 pid = task->pid;

    if (pid)
        bpf_printk("pid %u", pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
