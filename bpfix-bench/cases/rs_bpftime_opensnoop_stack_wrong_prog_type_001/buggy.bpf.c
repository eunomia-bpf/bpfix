#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif

struct args_t {
    int flags;
};

struct event_t {
    __u32 pid;
    __s32 ret;
    __u64 callers[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct args_t);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline int emit_open_stack(void *ctx, __s32 ret)
{
    __u32 pid = bpf_get_current_pid_tgid();
    struct args_t *args = bpf_map_lookup_elem(&start, &pid);
    struct event_t event = {};
    __u64 stack[3] = {};

    if (!args)
        return 0;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ret = ret;
    bpf_get_stack(ctx, &stack, sizeof(stack), BPF_F_USER_STACK);
    event.callers[0] = stack[1];
    event.callers[1] = stack[2];
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return args->flags;
}

SEC("xdp")
int rs_bpftime_opensnoop_stack_wrong_prog_type(struct xdp_md *ctx)
{
    if (emit_open_stack(ctx, 0))
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
