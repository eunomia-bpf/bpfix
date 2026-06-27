// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/if_ether.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

struct test_info {
	int x;
	struct bpf_dynptr ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bpf_dynptr);
}

array_map1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct test_info);
}

array_map2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
}

array_map3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
}

array_map4 SEC(".maps");

struct sample {
	int pid;
	long value;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
}

ringbuf SEC(".maps");

int err, val;

static int get_map_val_dynptr(struct bpf_dynptr *ptr)
{
	__u32 key = 0, *map_val;

	bpf_map_update_elem(&array_map3, &key, &val, 0);

	map_val = bpf_map_lookup_elem(&array_map3, &key);
	if (!map_val)
		return -ENOENT;

	bpf_dynptr_from_mem(map_val, sizeof(*map_val), 0, ptr);

	return 0;
}

/* A globally-defined bpf_dynptr can't be used (it must reside as a stack frame) */
struct bpf_dynptr global_dynptr;

__u32 hdr_size = sizeof(struct ethhdr);

static int callback(__u32 index, void *data)
{
        *(__u32 *)data = 123;

        return 0;
}

/* If the dynptr is written into in a callback function, its data
 * slices should be invalidated as well.
 */
SEC("?raw_tp")
__failure __msg("invalid mem access 'scalar'")
int invalid_data_slices(void *ctx)
{
	struct bpf_dynptr ptr;
	__u32 *slice;

	if (get_map_val_dynptr(&ptr))
		return 0;

	slice = bpf_dynptr_data(&ptr, 0, sizeof(__u32));
	if (!slice)
		return 0;

	bpf_loop(10, callback, &ptr, 0);

	/* this should fail */
	*slice = 1;

	return 0;
}
