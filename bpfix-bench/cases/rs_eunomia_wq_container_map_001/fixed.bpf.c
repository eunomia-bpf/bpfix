// SPDX-License-Identifier: GPL-2.0
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

#define bpf_wq_set_callback(wq, cb, flags) \
	bpf_wq_set_callback_impl((wq), (cb), (flags), NULL)

struct wq_request {
	__u32 key;
	__u32 value;
	__u32 schedule;
	__u32 priority;
};

struct elem {
	__u32 value;
	__u32 scheduled;
	struct bpf_wq work;
};

struct stats {
	__u64 processed;
	__u64 skipped;
	__u64 scheduled;
	__u64 last_key;
	__u64 last_value;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, struct elem);
} work_items SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct stats);
} stats_map SEC(".maps");

static int wq_callback(void *map, int *key, void *value)
{
	struct elem *elem = value;

	elem->scheduled += 1000;
	elem->value += 1;
	return 0;
}

SEC("xdp")
int rs_eunomia_wq_container_map(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct wq_request *req = data;
	struct elem init = {};
	struct elem *elem;
	struct stats *stats;
	struct bpf_wq *wq;
	int stat_key = 0;
	int key;

	if ((void *)(req + 1) > data_end)
		return XDP_PASS;

	stats = bpf_map_lookup_elem(&stats_map, &stat_key);
	if (!stats)
		return XDP_PASS;

	stats->processed++;
	if (!req->schedule) {
		stats->skipped++;
		return XDP_PASS;
	}

	key = (req->key ^ req->priority) & 3;
	init.value = req->value;
	if (bpf_map_update_elem(&work_items, &key, &init, BPF_ANY))
		return XDP_PASS;

	elem = bpf_map_lookup_elem(&work_items, &key);
	if (!elem)
		return XDP_PASS;

	wq = &elem->work;
	if (bpf_wq_init(wq, &work_items, 0))
		return XDP_PASS;

	elem->value = req->value;
	elem->scheduled = 1;

	if (bpf_wq_set_callback(wq, wq_callback, 0))
		return XDP_PASS;
	if (bpf_wq_start(wq, 0))
		return XDP_PASS;

	stats->scheduled++;
	stats->last_key = key;
	stats->last_value = elem->value + req->priority;
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
