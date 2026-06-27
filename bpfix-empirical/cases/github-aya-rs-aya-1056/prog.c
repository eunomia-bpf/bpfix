#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("uprobe")
int prog(struct pt_regs *ctx)
{
    char buf[16] = {};
    __s64 off = (__s32)bpf_get_prandom_u32();
    char *p = buf + off;
    return *p;
}

char LICENSE[] SEC("license") = "GPL";
