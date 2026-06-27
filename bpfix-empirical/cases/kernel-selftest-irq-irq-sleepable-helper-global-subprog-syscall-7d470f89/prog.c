// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

unsigned long global_flags;

extern void bpf_local_irq_save(unsigned long *) __weak __ksym;

extern void bpf_local_irq_restore(unsigned long *) __weak __ksym;

extern int bpf_copy_from_user_str(void *dst, u32 dst__sz, const void *unsafe_ptr__ign, u64 flags) __weak __ksym;

struct bpf_res_spin_lock lockA __hidden SEC(".data.A");

struct bpf_res_spin_lock lockB __hidden SEC(".data.B");

int __noinline
global_sleepable_helper_subprog(int i)
{
	if (i)
		bpf_copy_from_user(&i, sizeof(i), NULL);
	return i;
}

SEC("?syscall")
__failure __msg("global functions that may sleep are not allowed in non-sleepable context")
int irq_sleepable_helper_global_subprog(void *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	global_sleepable_helper_subprog(0);
	bpf_local_irq_restore(&flags);
	return 0;
}

char _license[] SEC("license") = "GPL";
