#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_getpid")
__attribute__((naked)) int prog(struct pt_regs *ctx)
{
    asm volatile ("exit");
}

char LICENSE[] SEC("license") = "GPL";
