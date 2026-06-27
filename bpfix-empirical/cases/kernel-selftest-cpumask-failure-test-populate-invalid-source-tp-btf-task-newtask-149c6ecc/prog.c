// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#include "cpumask_common.h"

char _license[] SEC("license") = "GPL";

struct kptr_nested_array_2 {
	struct bpf_cpumask __kptr * mask;
};

struct kptr_nested_array_1 {
	/* Make btf_parse_fields() in map_create() return -E2BIG */
	struct kptr_nested_array_2 d_2[CPUMASK_KPTR_FIELDS_MAX + 1];
};

struct kptr_nested_array {
	struct kptr_nested_array_1 d_1;
};

private(MASK_NESTED) static struct kptr_nested_array global_mask_nested_arr;

SEC("tp_btf/task_newtask")
__failure __msg("leads to invalid memory access")
int BPF_PROG(test_populate_invalid_source, struct task_struct *task, u64 clone_flags)
{
	void *garbage = (void *)0x123456;
	struct bpf_cpumask *local;
	int ret;

	local = create_cpumask();
	if (!local) {
		err = 1;
		return 0;
	}

	ret = bpf_cpumask_populate((struct cpumask *)local, garbage, 8);
	if (!ret)
		err = 2;

	bpf_cpumask_release(local);

	return 0;
}
