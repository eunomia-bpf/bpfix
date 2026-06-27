// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

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
__failure __msg("invalid read from stack")
int __naked read_from_iter_slot_fail(void)
{
	asm volatile (
		/* r6 points to struct bpf_iter_num on the stack */
		"r6 = r10;"
		"r6 += -24;"

		/* create iterator */
		"r1 = r6;"
		"r2 = 0;"
		"r3 = 1000;"
		"call %[bpf_iter_num_new];"

		/* attempt to leak bpf_iter_num state */
		"r7 = *(u64 *)(r6 + 0);"
		"r8 = *(u64 *)(r6 + 8);"

		/* destroy iterator */
		"r1 = r6;"
		"call %[bpf_iter_num_destroy];"

		/* leak bpf_iter_num state */
		"r0 = r7;"
		"if r7 > r8 goto +1;"
		"r0 = r8;"
		"exit;"
		:
		: ITER_HELPERS
		: __clobber_common, "r6", "r7", "r8"
	);
}

int zero;
