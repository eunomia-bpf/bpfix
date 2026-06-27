#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

const volatile char targ_comm[TASK_COMM_LEN] = "abcdefghijklmnop";

static __always_inline bool comm_allowed(const char *comm)
{
    int i;

    for (i = 0; targ_comm[i] != '\0' && i < TASK_COMM_LEN; i++) {
        if (comm[i] != targ_comm[i])
            return false;
    }
    return true;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(prog, struct task_struct *task, unsigned long clone_flags)
{
    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(comm, sizeof(comm));
    return comm_allowed(comm);
}

char LICENSE[] SEC("license") = "GPL";
