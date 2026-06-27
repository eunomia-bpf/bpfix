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
__failure __msg("expected an initialized iter_num as arg #0")
int compromise_iter_w_helper_write_fail(void *ctx)
{
	struct bpf_iter_num iter;

	asm volatile (
		/* create iterator */
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 1000;"
		"call %[bpf_iter_num_new];"

		/* overwrite 8th byte with bpf_probe_read_kernel() */
		"r1 = %[iter];"
		"r1 += 7;"
		"r2 = 1;"
		"r3 = 0;" /* NULL */
		"call %[bpf_probe_read_kernel];"

		/* (attempt to) destroy iterator */
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter), ITER_HELPERS, __imm(bpf_probe_read_kernel)
		: __clobber_common
	);

	return 0;
}

int zero;
