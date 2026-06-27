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

/* A globally-defined bpf_dynptr can't be used (it must reside as a stack frame) */
struct bpf_dynptr global_dynptr;

/* The read-only data slice is invalidated whenever a helper changes packet data */
SEC("?xdp")
__failure __msg("invalid mem access 'scalar'")
int xdp_invalid_data_slice1(struct xdp_md *xdp)
{
	struct bpf_dynptr ptr;
	struct ethhdr *hdr;
	char buffer[sizeof(*hdr)] = {};

	bpf_dynptr_from_xdp(xdp, 0, &ptr);
	hdr = bpf_dynptr_slice(&ptr, 0, buffer, sizeof(buffer));
	if (!hdr)
		return SK_DROP;

	val = hdr->h_proto;

	if (bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(*hdr)))
		return XDP_DROP;

	/* this should fail */
	val = hdr->h_proto;

	return XDP_PASS;
}

__u32 hdr_size = sizeof(struct ethhdr);
