#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u64 *state_ptr;

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_btf, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    if (!preempt || state_ptr == 0)
        return 0;

    bpf_printk("State: %px", state_ptr);
    __sync_val_compare_and_swap(state_ptr, 0, 1);
    return 0;
}

char _license[] SEC("license") = "GPL";
