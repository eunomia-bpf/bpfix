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
__failure __msg("Possibly NULL pointer passed to helper arg2")
int BPF_PROG(test_global_mask_rcu_no_null_check, struct task_struct *task, u64 clone_flags)
{
	struct bpf_cpumask *prev, *curr;

	curr = bpf_cpumask_create();
	if (!curr)
		return 0;

	prev = bpf_kptr_xchg(&global_mask, curr);
	if (prev)
		bpf_cpumask_release(prev);

	bpf_rcu_read_lock();
	curr = global_mask;
	/* PTR_TO_BTF_ID | PTR_MAYBE_NULL | MEM_RCU passed to bpf_kptr_xchg() */
	prev = bpf_kptr_xchg(&global_mask, curr);
	bpf_rcu_read_unlock();
	if (prev)
		bpf_cpumask_release(prev);

	return 0;
}
