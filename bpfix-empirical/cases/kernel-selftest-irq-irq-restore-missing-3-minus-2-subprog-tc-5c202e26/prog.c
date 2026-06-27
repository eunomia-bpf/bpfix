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

static __noinline void local_irq_save(unsigned long *flags)
{
	bpf_local_irq_save(flags);
}

static __noinline void local_irq_restore(unsigned long *flags)
{
	bpf_local_irq_restore(flags);
}

SEC("?tc")
__failure __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region")
int irq_restore_missing_3_minus_2_subprog(struct __sk_buff *ctx)
{
	unsigned long flags1;
	unsigned long flags2;
	unsigned long flags3;

	local_irq_save(&flags1);
	local_irq_save(&flags2);
	local_irq_save(&flags3);
	local_irq_restore(&flags3);
	local_irq_restore(&flags2);
	return 0;
}

char _license[] SEC("license") = "GPL";
