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

/* Can't pass in a dynptr as an arg to a helper function that doesn't take in a
 * dynptr argument
 */
SEC("?raw_tp")
__failure __msg("invalid read from stack")
int invalid_helper1(void *ctx)
{
	struct bpf_dynptr ptr;

	get_map_val_dynptr(&ptr);

	/* this should fail */
	bpf_strncmp((const char *)&ptr, sizeof(ptr), "hello!");

	return 0;
}

/* A globally-defined bpf_dynptr can't be used (it must reside as a stack frame) */
struct bpf_dynptr global_dynptr;

__u32 hdr_size = sizeof(struct ethhdr);
