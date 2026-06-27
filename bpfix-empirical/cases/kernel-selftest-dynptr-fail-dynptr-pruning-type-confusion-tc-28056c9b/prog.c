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

SEC("?tc")
__failure __msg("cannot overwrite referenced dynptr") __log_level(2)
int dynptr_pruning_type_confusion(struct __sk_buff *ctx)
{
	asm volatile (
		"r6 = %[array_map4] ll;			\
		 r7 = %[ringbuf] ll;			\
		 r1 = r6;				\
		 r2 = r10;				\
		 r2 += -8;				\
		 r9 = 0;				\
		 *(u64 *)(r2 + 0) = r9;			\
		 r3 = r10;				\
		 r3 += -24;				\
		 r9 = 0xeB9FeB9F;			\
		 *(u64 *)(r10 - 16) = r9;		\
		 *(u64 *)(r10 - 24) = r9;		\
		 r9 = 0;				\
		 r4 = 0;				\
		 r8 = r2;				\
		 call %[bpf_map_update_elem];		\
		 r1 = r6;				\
		 r2 = r8;				\
		 call %[bpf_map_lookup_elem];		\
		 if r0 != 0 goto tjmp1;			\
		 exit;					\
	tjmp1:						\
		 r8 = r0;				\
		 r1 = r7;				\
		 r2 = 8;				\
		 r3 = 0;				\
		 r4 = r10;				\
		 r4 += -16;				\
		 r0 = *(u64 *)(r0 + 0);			\
		 call %[bpf_ringbuf_reserve_dynptr];	\
		 if r0 == 0 goto tjmp2;			\
		 r8 = r8;				\
		 r8 = r8;				\
		 r8 = r8;				\
		 r8 = r8;				\
		 r8 = r8;				\
		 r8 = r8;				\
		 r8 = r8;				\
		 goto tjmp3;				\
	tjmp2:						\
		 *(u64 *)(r10 - 8) = r9;		\
		 *(u64 *)(r10 - 16) = r9;		\
		 r1 = r8;				\
		 r1 += 8;				\
		 r2 = 0;				\
		 r3 = 0;				\
		 r4 = r10;				\
		 r4 += -16;				\
		 call %[bpf_dynptr_from_mem];		\
	tjmp3:						\
		 r1 = r10;				\
		 r1 += -16;				\
		 r2 = 0;				\
		 call %[bpf_ringbuf_discard_dynptr];	"
		:
		: __imm(bpf_map_update_elem),
		  __imm(bpf_map_lookup_elem),
		  __imm(bpf_ringbuf_reserve_dynptr),
		  __imm(bpf_dynptr_from_mem),
		  __imm(bpf_ringbuf_discard_dynptr),
		  __imm_addr(array_map4),
		  __imm_addr(ringbuf)
		: __clobber_all
	);
	return 0;
}

__u32 hdr_size = sizeof(struct ethhdr);
