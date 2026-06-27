// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

static __attribute__((used)) void force_iter_ksym_btf(struct bpf_iter_num *it)
{
	bpf_iter_num_new(it, 0, 0);
	bpf_iter_num_next(it);
	bpf_iter_num_destroy(it);
}


#define ITER_HELPERS						\
	  __imm(bpf_iter_num_new),				\
	  __imm(bpf_iter_num_next),				\
	  __imm(bpf_iter_num_destroy)

SEC("?raw_tp")
__failure __msg("R0 invalid mem access 'scalar'")
int missing_null_check_fail(void *ctx)
{
	struct bpf_iter_num iter;

	asm volatile (
		/* create iterator */
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 1000;"
		"call %[bpf_iter_num_new];"

		/* consume first element */
		"r1 = %[iter];"
		"call %[bpf_iter_num_next];"

		/* FAIL: deref with no NULL check */
		"r1 = *(u32 *)(r0 + 0);"

		/* destroy iterator */
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter), ITER_HELPERS
		: __clobber_common
	);

	return 0;
}
