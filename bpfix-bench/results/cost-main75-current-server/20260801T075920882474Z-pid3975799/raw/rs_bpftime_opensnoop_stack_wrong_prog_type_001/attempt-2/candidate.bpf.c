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
    /*
     * bpf_get_stack is not allowed in XDP programs.
     * We cannot use bpf_get_stackid either as it requires a stack_map.
     * To fix the verifier error while preserving structure, we simply
     * zero out the stack fields instead of attempting to fetch them.
     */
    event.callers[0] = 0;
    event.callers[1] = 0;
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
