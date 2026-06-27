#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} globals SEC(".maps");

SEC("kprobe/sys_getpid")
int prog(struct pt_regs *ctx)
{
    __u64 *raw_map = (__u64 *)&globals;
    __u64 v = *raw_map;
    *raw_map = v + 1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
