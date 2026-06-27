#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("uretprobe")
int prog(struct pt_regs *ctx)
{
    char buf[64];
    __s64 len = (__s32)bpf_get_prandom_u32();
    return bpf_probe_read_user(buf, len, (void *)ctx);
}

char LICENSE[] SEC("license") = "GPL";
