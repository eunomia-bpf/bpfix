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

SEC("?tc")
__failure __msg("cannot restore irq state out of order")
int irq_ooo_lock_cond_inv(struct __sk_buff *ctx)
{
	unsigned long flags1, flags2;

	if (bpf_res_spin_lock_irqsave(&lockA, &flags1))
		return 0;
	if (bpf_res_spin_lock_irqsave(&lockB, &flags2)) {
		bpf_res_spin_unlock_irqrestore(&lockA, &flags1);
		return 0;
	}

	bpf_res_spin_unlock_irqrestore(&lockB, &flags1);
	bpf_res_spin_unlock_irqrestore(&lockA, &flags2);
	return 0;
}

char _license[] SEC("license") = "GPL";
