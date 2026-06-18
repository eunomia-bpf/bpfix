#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#define RS_DETAIL_LEN 8
#define RS_EVENT_TYPE_WRITE 15

struct rs_agg_key {
    __u32 pid;
    __u32 event_type;
    char detail[RS_DETAIL_LEN];
};

struct rs_agg_value {
    __u64 count;
    __u64 total_bytes;
    __s32 last_fd;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u64);
    __type(value, __s32);
} write_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, struct rs_agg_key);
    __type(value, struct rs_agg_value);
} event_agg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} agg_overflow_count SEC(".maps");

static __always_inline void rs_format_fd_detail(char detail[RS_DETAIL_LEN], __s32 fd)
{
    __builtin_memset(detail, 0, RS_DETAIL_LEN);
    detail[0] = 'f';
    detail[1] = 'd';
    detail[2] = '=';
    if (fd < 0) {
        detail[3] = '-';
        fd = -fd;
        detail[4] = '0' + (fd % 10);
    } else {
        detail[3] = '0' + (fd % 10);
    }
}

static __always_inline int rs_update_agg_map(struct rs_agg_key *key, __u64 bytes,
                                             __s32 fd)
{
    struct rs_agg_value *val = bpf_map_lookup_elem(&event_agg_map, key);

    if (val) {
        val->count += 1;
        val->total_bytes += bytes;
        val->last_fd = fd;
        return 1;
    } else {
        struct rs_agg_value fresh = {};

        fresh.count = 1;
        fresh.total_bytes = bytes;
        fresh.last_fd = fd;
        if (bpf_map_update_elem(&event_agg_map, key, &fresh, BPF_NOEXIST) < 0) {
            __u32 zero = 0;
            __u64 *overflow = bpf_map_lookup_elem(&agg_overflow_count, &zero);

            if (overflow)
                *overflow += 1;
            return 0;
        }
        return 1;
    }
}

SEC("xdp")
int rs_agentsight_write_ctx_merge(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *bytes = data;
    struct rs_agg_key key = {};
    __s32 *fd_ptr;
    __u64 id;
    __u32 pid;
    __u32 tid;
    __u32 ret;
    __u8 guarded;
    __s32 fd;

    if ((void *)(bytes + 5) > data_end)
        return XDP_PASS;

    pid = bytes[0];
    tid = bytes[1];
    ret = bytes[2];
    guarded = bytes[3];
    id = ((__u64)pid << 32) | tid;

    if (ret == 0)
        return XDP_PASS;

    fd_ptr = bpf_map_lookup_elem(&write_ctx_map, &id);
    if (guarded & 1) {
        if (!fd_ptr)
            return XDP_PASS;
    }

    fd = *fd_ptr;
    bpf_map_delete_elem(&write_ctx_map, &id);

    key.pid = pid;
    key.event_type = RS_EVENT_TYPE_WRITE;
    rs_format_fd_detail(key.detail, fd);

    if (rs_update_agg_map(&key, ret, fd))
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
