// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MSG_DATA_ARG_LEN 32
#define MSG_DATA_ARG_OFFSET 8
#define MSG_OP_DATA 10

struct msg_common {
    __u32 op;
    __u32 size;
};

struct msg_data {
    struct msg_common common;
    __u8 arg[MSG_DATA_ARG_LEN];
};

struct data_event_desc {
    __u32 size;
    __u32 leftover;
    int error;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct msg_data);
} data_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, __u32);
} events SEC(".maps");

static __always_inline long submit_data_bytes(
    void *ctx,
    struct msg_data *msg,
    struct data_event_desc *desc,
    unsigned long user_ptr,
    __u64 bytes)
{
    int err;

    msg->common.op = MSG_OP_DATA;
    err = bpf_probe_read_user(&msg->arg[0], bytes, (const void *)user_ptr);
    if (err < 0) {
        desc->error = err;
        desc->size = 0;
        desc->leftover = 0;
        return err;
    }

    msg->common.size = MSG_DATA_ARG_OFFSET + bytes;
    err = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, msg, msg->common.size);
    if (err < 0) {
        desc->error = err;
        desc->size = 0;
        desc->leftover = 0;
        return err;
    }

    desc->error = 0;
    desc->size = bytes;
    desc->leftover = 0;
    return bytes;
}

SEC("tracepoint/syscalls/sys_enter_write")
int rs_tetragon_data_event_size_guard(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    struct data_event_desc desc = {};
    struct msg_data *msg;
    unsigned long user_ptr;
    __u64 raw_size;
    __u64 bounded_size;

    msg = bpf_map_lookup_elem(&data_heap, &zero);
    if (!msg)
        return 0;

    user_ptr = ctx->args[1];
    raw_size = ctx->args[2];
    raw_size &= 0x7fffffff;
    bounded_size = raw_size;
    if (bounded_size > MSG_DATA_ARG_LEN)
        bounded_size = MSG_DATA_ARG_LEN;

    desc.size = bounded_size;
    return submit_data_bytes(ctx, msg, &desc, user_ptr, bounded_size);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
