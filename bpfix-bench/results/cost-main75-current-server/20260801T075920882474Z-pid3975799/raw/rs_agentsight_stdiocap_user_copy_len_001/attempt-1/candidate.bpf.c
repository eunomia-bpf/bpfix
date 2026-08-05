#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct io_args_t {
    __u64 buf;
    __s32 fd;
    __u8 is_read;
};

struct stdio_event_t {
    __u32 pid;
    __s32 fd;
    __u32 len;
    __u8 is_read;
    __u8 pad[3];
    char buf[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct io_args_t);
} io_args SEC(".maps");

SEC("tp/syscalls/sys_exit_read")
int rs_agentsight_stdiocap_user_copy_len(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct io_args_t *args;
    struct stdio_event_t *event;
    __u32 copy_size = 8;

    args = bpf_map_lookup_elem(&io_args, &pid_tgid);
    if (!args)
        return 0;
    if (ctx->ret <= 0)
        goto cleanup;

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        goto cleanup;

    event->pid = pid_tgid >> 32;
    event->fd = args->fd;
    event->len = (__u32)ctx->ret;
    event->is_read = args->is_read;
    bpf_probe_read_user(event->buf, copy_size, (const void *)args->buf);
    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&io_args, &pid_tgid);
    return 0;
}

char _license[] SEC("license") = "GPL";
