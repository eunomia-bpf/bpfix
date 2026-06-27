#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_BUF_SIZE 16
#define DATA_BUF_SIZE 16
#define MAX_ENTRIES 10240

struct ssl_event {
    __u64 timestamp_ns;
    __u64 delta_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 len;
    __u32 buf_filled;
    __u32 rw;
    char comm[16];
    char buf[DATA_BUF_SIZE];
};

#define BASE_EVENT_SIZE ((__u64)(&((struct ssl_event *)0)->buf))
#define EVENT_SIZE(x) (BASE_EVENT_SIZE + ((__u64)(x)))

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} perf_SSL_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ssl_event);
} ssl_data SEC(".maps");

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

SEC("uretprobe/SSL_read")
int rs_bpftime_sslsniff_perf_copy_len(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 uid = bpf_get_current_uid_gid();
    __u64 ts = bpf_ktime_get_ns();
    __u32 zero = 0;
    struct ssl_event *data;
    __u64 *bufp;
    __u64 *tsp;
    __u32 copy_size;
    int ret;
    int len = PT_REGS_RC(ctx);

    if (len <= 0)
        return 0;

    bufp = bpf_map_lookup_elem(&bufs, &tid);
    if (!bufp)
        return 0;

    tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (!tsp)
        return 0;

    data = bpf_map_lookup_elem(&ssl_data, &zero);
    if (!data)
        return 0;

    data->timestamp_ns = ts;
    data->delta_ns = ts - *tsp;
    data->pid = pid;
    data->tid = tid;
    data->uid = uid;
    data->len = (__u32)len;
    data->buf_filled = 0;
    data->rw = 0;
    bpf_get_current_comm(data->comm, sizeof(data->comm));

    copy_size = (__u32)len;
    if (copy_size > MAX_BUF_SIZE)
        copy_size = MAX_BUF_SIZE;

    ret = bpf_probe_read_user(data->buf, copy_size, (void *)*bufp);
    if (!ret)
        data->buf_filled = 1;
    else
        copy_size = 0;

    bpf_map_delete_elem(&bufs, &tid);
    bpf_map_delete_elem(&start_ns, &tid);
    bpf_perf_event_output(ctx, &perf_SSL_events, BPF_F_CURRENT_CPU, data, EVENT_SIZE(copy_size));
    return 0;
}

char _license[] SEC("license") = "GPL";
