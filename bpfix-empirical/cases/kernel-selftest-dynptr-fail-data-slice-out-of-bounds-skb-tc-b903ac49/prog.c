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

/* A data slice can't be accessed out of bounds */
SEC("?tc")
__failure __msg("value is outside of the allowed memory range")
int data_slice_out_of_bounds_skb(struct __sk_buff *skb)
{
	struct bpf_dynptr ptr;
	struct ethhdr *hdr;
	char buffer[sizeof(*hdr)] = {};

	bpf_dynptr_from_skb(skb, 0, &ptr);

	hdr = bpf_dynptr_slice_rdwr(&ptr, 0, buffer, sizeof(buffer));
	if (!hdr)
		return SK_DROP;

	/* this should fail */
	*(__u8*)(hdr + 1) = 1;

	return SK_PASS;
}

/* A globally-defined bpf_dynptr can't be used (it must reside as a stack frame) */
struct bpf_dynptr global_dynptr;

__u32 hdr_size = sizeof(struct ethhdr);
