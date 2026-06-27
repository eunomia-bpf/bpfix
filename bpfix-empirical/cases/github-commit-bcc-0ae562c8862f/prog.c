#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define FUNC_MAX_STACK_DEPTH 64
#define FUNC_STACK_DEPTH_MASK 63

struct func_stack {
    __u64 ips[FUNC_MAX_STACK_DEPTH];
    __u64 stack_depth;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct func_stack);
} stacks SEC(".maps");

SEC("kprobe/do_sys_openat2")
int prog(struct pt_regs *ctx)
{
    __u32 key = 0;
    struct func_stack *func_stack = bpf_map_lookup_elem(&stacks, &key);
    if (!func_stack)
        return 0;

    __s64 stack_depth = func_stack->stack_depth;
    __u64 last_ip = 0;

    if (stack_depth >= FUNC_MAX_STACK_DEPTH - 1)
        return 0;

    __s64 last_stack_depth = stack_depth - 1;
    if (last_stack_depth >= 0 && last_stack_depth < FUNC_MAX_STACK_DEPTH)
        last_ip = func_stack->ips[last_stack_depth];

    func_stack->ips[stack_depth] = bpf_get_func_ip(ctx) + last_ip;
    stack_depth = (stack_depth + 1) & FUNC_STACK_DEPTH_MASK;
    func_stack->stack_depth = stack_depth;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
