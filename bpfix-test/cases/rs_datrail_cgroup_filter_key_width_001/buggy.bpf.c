// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u64);
    __type(value, __u8);
} tracked_cgroups SEC(".maps");

const volatile bool filter_cgroup = true;
const volatile bool filter_cgroup_children = true;
const volatile __u64 target_cgroup_id = 0x42;
volatile __u64 child_hit_count;
volatile __u32 last_child_selector;

static __always_inline int datrail_is_cgroup_tracked_from_packet(__u8 selector)
{
    if (!filter_cgroup)
        return 1;

    __u64 current_cgroup_id = selector;
    if (current_cgroup_id == target_cgroup_id)
        return 1;

    if (!filter_cgroup_children)
        return 0;

    __u32 child_cgroup_id = selector;
    __u8 *tracked = bpf_map_lookup_elem(&tracked_cgroups, &child_cgroup_id);

    if (!tracked)
        return 0;
    return *tracked != 0;
}

static __always_inline void datrail_update_agg(__u8 selector)
{
    child_hit_count += 1;
    last_child_selector = selector;
}

SEC("xdp")
int rs_datrail_cgroup_filter_key_width(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 1 > data_end)
        return XDP_PASS;

    __u8 selector = *(__u8 *)data;
    if (selector == 0)
        return XDP_PASS;

    if (!datrail_is_cgroup_tracked_from_packet(selector))
        return XDP_PASS;

    datrail_update_agg(selector);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
