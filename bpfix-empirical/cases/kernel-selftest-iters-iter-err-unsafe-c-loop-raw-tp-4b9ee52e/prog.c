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
__failure __msg("math between map_value pointer and register with unbounded min value is not allowed")
int iter_err_unsafe_c_loop(const void *ctx)
{
	struct bpf_iter_num it;
	int *v, i = zero; /* obscure initial value of i */

	MY_PID_GUARD();

	bpf_iter_num_new(&it, 0, 1000);
	while ((v = bpf_iter_num_next(&it))) {
		i++;
	}
	bpf_iter_num_destroy(&it);

	small_arr[i] = 123; /* invalid */

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
