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

#define DETAIL_LEN 8
#define MAX_FILENAME_LEN 32
#define EVENT_TYPE_FILE_DELETE 15

struct agg_key {
    __u32 pid;
    __u32 event_type;
    char detail[DETAIL_LEN];
};

struct agg_value {
    __u64 count;
    __u64 last_marker;
    char extra[DETAIL_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, struct agg_key);
    __type(value, struct agg_value);
} event_agg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} agg_overflow_count SEC(".maps");

static __u32 trace_fs_mutations = 1;

static __always_inline void copy_detail(char *dst, const char *src)
{
#pragma unroll
    for (int i = 0; i < DETAIL_LEN; i++)
        dst[i] = src[i];
}

static __always_inline void extract_dir_prefix(const char *path, char *out)
{
    int last_slash = 0;

#pragma unroll
    for (int i = 0; i < DETAIL_LEN - 1; i++) {
        char c = path[i];
        if (c == '\0')
            break;
        if (c == '/')
            last_slash = i;
        out[i] = c;
    }

    if (last_slash > 0)
        out[last_slash] = '\0';
}

static __always_inline int aggregate_path_event(void *data, void *data_end)
{
    if (!trace_fs_mutations)
        return XDP_PASS;
    if (data + 3 + MAX_FILENAME_LEN > data_end)
        return XDP_PASS;

    __u8 pid_byte = *(__u8 *)data;
    __u8 event_selector = *(__u8 *)(data + 1);
    __u8 guarded_overflow = *(__u8 *)(data + 2);
    const char *packet_path = data + 3;

    if (event_selector == 0)
        return XDP_PASS;

    char filepath[MAX_FILENAME_LEN] = {};
#pragma unroll
    for (int i = 0; i < MAX_FILENAME_LEN; i++)
        filepath[i] = packet_path[i];

    struct agg_key key = {};
    key.pid = pid_byte;
    key.event_type = EVENT_TYPE_FILE_DELETE;
    extract_dir_prefix(filepath, key.detail);

    struct agg_value *val = bpf_map_lookup_elem(&event_agg_map, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
        val->last_marker = pid_byte;
        copy_detail(val->extra, key.detail);
        return XDP_DROP;
    }

    struct agg_value new_val = {};
    new_val.count = 1;
    new_val.last_marker = pid_byte;
    copy_detail(new_val.extra, key.detail);

    if (bpf_map_update_elem(&event_agg_map, &key, &new_val, BPF_NOEXIST) < 0) {
        __u32 zero = 0;
        __u64 *overflow = bpf_map_lookup_elem(&agg_overflow_count, &zero);

        if (!overflow)
            return XDP_PASS;

        if (guarded_overflow & 1) {
            __u32 shadow_zero = guarded_overflow;
            __u64 *shadow_overflow = bpf_map_lookup_elem(&agg_overflow_count, &shadow_zero);

            if (shadow_overflow)
                __sync_fetch_and_add(shadow_overflow, 1);
        }

        __sync_fetch_and_add(overflow, 1);
    }

    return XDP_DROP;
}

SEC("xdp")
int rs_agentsight_fs_overflow_counter_merge(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    return aggregate_path_event(data, data_end);
}

char _license[] SEC("license") = "GPL";
