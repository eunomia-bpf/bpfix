// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define NAME_LEN 80

struct args_t {
    const char *fname;
    int flags;
};

struct event {
    __u64 ts;
    __u32 pid;
    __u32 uid;
    int ret;
    int flags;
    char comm[TASK_COMM_LEN];
    char fname[NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct args_t);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int rs_bpftime_opensnoop_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id;
    struct args_t args = {};

    args.fname = (const char *)ctx->args[1];
    args.flags = (int)ctx->args[2];
    bpf_map_update_elem(&start, &pid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int rs_bpftime_opensnoop_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 pid = id;
    struct args_t *ap;
    struct event *event;
    int ret = (int)ctx->ret;

    ap = bpf_map_lookup_elem(&start, &pid);
    if (!ap)
        return 0;

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        goto cleanup;

    if (ret >= 0)
        return 0;

    event->ts = bpf_ktime_get_ns();
    event->pid = tgid;
    event->uid = bpf_get_current_uid_gid();
    event->ret = ret;
    event->flags = ap->flags;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->fname, sizeof(event->fname), ap->fname);
    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&start, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
