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
__failure __msg("R2 must be a rcu pointer")
int BPF_PROG(test_global_mask_out_of_rcu, struct task_struct *task, u64 clone_flags)
{
	struct bpf_cpumask *local, *prev;

	local = create_cpumask();
	if (!local)
		return 0;

	prev = bpf_kptr_xchg(&global_mask, local);
	if (prev) {
		bpf_cpumask_release(prev);
		err = 3;
		return 0;
	}

	bpf_rcu_read_lock();
	local = global_mask;
	if (!local) {
		err = 4;
		bpf_rcu_read_unlock();
		return 0;
	}

	bpf_rcu_read_unlock();

	/* RCU region is exited before calling KF_RCU kfunc. */

	bpf_cpumask_test_cpu(0, (const struct cpumask *)local);

	return 0;
}
