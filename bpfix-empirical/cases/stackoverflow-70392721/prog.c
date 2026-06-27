#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 42);
    __type(key, int);
    __type(value, int);
} my_map SEC(".maps");

SEC("kprobe/sys_write")
int bpf_prog1(struct pt_regs *ctx)
{
    struct S {
        int pid;
        int cookie;
    } data;

    data.pid = bpf_get_current_pid_tgid();
    data.cookie = 99;

    bpf_perf_event_output(ctx, &my_map, 0, &data, sizeof(data));

    return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 190;
