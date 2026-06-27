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
__failure __msg("dynptr has to be at a constant offset") __log_level(2)
int dynptr_var_off_overwrite(struct __sk_buff *ctx)
{
	asm volatile (
		"r9 = 16;				\
		 *(u32 *)(r10 - 4) = r9;		\
		 r8 = *(u32 *)(r10 - 4);		\
		 if r8 >= 0 goto vjmp1;			\
		 r0 = 1;				\
		 exit;					\
	vjmp1:						\
		 if r8 <= 16 goto vjmp2;		\
		 r0 = 1;				\
		 exit;					\
	vjmp2:						\
		 r8 &= 16;				\
		 r1 = %[ringbuf] ll;			\
		 r2 = 8;				\
		 r3 = 0;				\
		 r4 = r10;				\
		 r4 += -32;				\
		 r4 += r8;				\
		 call %[bpf_ringbuf_reserve_dynptr];	\
		 r9 = 0xeB9F;				\
		 *(u64 *)(r10 - 16) = r9;		\
		 r1 = r10;				\
		 r1 += -32;				\
		 r1 += r8;				\
		 r2 = 0;				\
		 call %[bpf_ringbuf_discard_dynptr];	"
		:
		: __imm(bpf_ringbuf_reserve_dynptr),
		  __imm(bpf_ringbuf_discard_dynptr),
		  __imm_addr(ringbuf)
		: __clobber_all
	);
	return 0;
}

__u32 hdr_size = sizeof(struct ethhdr);
