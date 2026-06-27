// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_compiler.h"

static volatile int zero = 0;

int my_pid;

int arr[256];

int small_arr[16] SEC(".data.small_arr");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, int);
	__type(value, int);
}

amap SEC(".maps");

#ifdef REAL_TEST

#define MY_PID_GUARD() if (my_pid != (bpf_get_current_pid_tgid() >> 32)) return 0

#else

#define MY_PID_GUARD() ({ })

#endif

SEC("?raw_tp")
__failure __msg("unbounded memory access")
int iter_err_unsafe_asm_loop(const void *ctx)
{
	struct bpf_iter_num it;

	MY_PID_GUARD();

	asm volatile (
		"r6 = %[zero];" /* iteration counter */
		"r1 = %[it];" /* iterator state */
		"r2 = 0;"
		"r3 = 1000;"
		"r4 = 1;"
		"call %[bpf_iter_num_new];"
	"loop:"
		"r1 = %[it];"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto out;"
		"r6 += 1;"
		"goto loop;"
	"out:"
		"r1 = %[it];"
		"call %[bpf_iter_num_destroy];"
		"r1 = %[small_arr];"
		"r2 = r6;"
		"r2 <<= 2;"
		"r1 += r2;"
		"*(u32 *)(r1 + 0) = r6;" /* invalid */
		:
		: [it]"r"(&it),
		  [small_arr]"r"(small_arr),
		  [zero]"r"(zero),
		  __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_next),
		  __imm(bpf_iter_num_destroy)
		: __clobber_common, "r6"
	);

	return 0;
}

static int arr2d[4][5];

static int arr2d_row_sums[4];

static int arr2d_col_sums[5];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1000);
}

hash_map SEC(".maps");

#define __bpf_memzero(p, sz) bpf_probe_read_kernel((p), (sz), 0)

struct {
	int data[32];
	int n;
}

loop_data;

__u32 upper, select_n, result;

__u64 global;

struct bpf_iter_num global_it;

char _license[] SEC("license") = "GPL";

static __attribute__((used)) void force_iter_ksym_btf(struct bpf_iter_num *it)
{
	bpf_iter_num_new(it, 0, 0);
	bpf_iter_num_next(it);
	bpf_iter_num_destroy(it);
}

