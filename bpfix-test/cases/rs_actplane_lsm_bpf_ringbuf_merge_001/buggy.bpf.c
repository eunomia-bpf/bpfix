#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

struct decision_event {
    __u32 pid;
    __u32 cmd;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} protected_pids SEC(".maps");

static __always_inline int active_policy(__u32 pid)
{
    __u32 *flag = bpf_map_lookup_elem(&protected_pids, &pid);
    return flag && *flag == 7;
}

SEC("lsm/bpf")
int BPF_PROG(rs_actplane_lsm_bpf_ringbuf_merge, int cmd, union bpf_attr *attr,
             unsigned int size, bool privileged)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct decision_event *event;

    (void)attr;
    (void)size;

    if (!active_policy(pid))
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event && privileged)
        return 0;

    event->pid = pid;
    event->cmd = (__u32)cmd;
    bpf_ringbuf_submit(event, 0);
    return -EPERM;
}

char _license[] SEC("license") = "GPL";
