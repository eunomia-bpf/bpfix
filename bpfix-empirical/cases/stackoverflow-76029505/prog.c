#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 socklen_t;

struct accept_args_t {
    struct sockaddr *addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u64);
    __type(value, struct accept_args_t);
} active_accept_args_map SEC(".maps");

SEC("kprobe/sys_accept")
int syscall__probe_entry_accept(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t value = { .addr = addr };

    bpf_map_update_elem(&active_accept_args_map, &id, &value, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
