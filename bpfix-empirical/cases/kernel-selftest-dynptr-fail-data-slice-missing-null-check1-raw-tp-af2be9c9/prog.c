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

/* A data slice must be first checked for NULL */
SEC("?raw_tp")
__failure __msg("invalid mem access 'mem_or_null'")
int data_slice_missing_null_check1(void *ctx)
{
	struct bpf_dynptr ptr;
	void *data;

	bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, &ptr);

	data  = bpf_dynptr_data(&ptr, 0, 8);

	/* missing if (!data) check */

	/* this should fail */
	*(__u8 *)data = 3;

	bpf_ringbuf_submit_dynptr(&ptr, 0);
	return 0;
}

/* A globally-defined bpf_dynptr can't be used (it must reside as a stack frame) */
struct bpf_dynptr global_dynptr;

__u32 hdr_size = sizeof(struct ethhdr);
