#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_BUF_SIZE 16
#define MAX_ENTRIES 1024

struct browser_event {
    __u64 delta_ns;
    __u32 pid;
    __u32 tid;
    __u32 len;
    __u32 buf_size;
    char buf[MAX_BUF_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} start_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} bufs SEC(".maps");

SEC("tp/syscalls/sys_exit_read")
int rs_datrail_browsertrace_start_ns_merge(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    struct browser_event *event;
    __u64 *bufp;
    __u64 *tsp;
    __u32 copy_size;
    int len = ctx->ret;

    if (len <= 0)
        return 0;

    bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (!bufp)
        return 0;

    tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (!tsp)
        return 0;

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->delta_ns = ts - *tsp;
    event->pid = pid;
    event->tid = tid;
    event->len = (__u32)len;
    event->buf_size = 0;

    copy_size = (__u32)len;
    if (copy_size > MAX_BUF_SIZE)
        copy_size = MAX_BUF_SIZE;

    if (!bpf_probe_read_user(event->buf, copy_size, (void *)*bufp))
        event->buf_size = copy_size;

    bpf_map_delete_elem(&bufs, &tid);
    bpf_map_delete_elem(&start_ns, &tid);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
