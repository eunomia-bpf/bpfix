#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

SEC("uretprobe")
int prog(struct pt_regs *ctx)
{
    char buf[64] = {};
    __s64 len = (__s32)bpf_get_prandom_u32();
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, buf, len);
}

char LICENSE[] SEC("license") = "GPL";
