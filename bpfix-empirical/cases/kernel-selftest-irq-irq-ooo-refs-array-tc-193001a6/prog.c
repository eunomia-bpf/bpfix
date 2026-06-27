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
int irq_ooo_refs_array(struct __sk_buff *ctx)
{
	unsigned long flags[4];
	struct { int i; } *p;

	/* refs=1 */
	bpf_local_irq_save(&flags[0]);

	/* refs=1,2 */
	p = bpf_obj_new(typeof(*p));
	if (!p) {
		bpf_local_irq_restore(&flags[0]);
		return 0;
	}

	/* refs=1,2,3 */
	bpf_local_irq_save(&flags[1]);

	/* refs=1,2,3,4 */
	bpf_local_irq_save(&flags[2]);

	/* Now when we remove ref=2, the verifier must not break the ordering in
	 * the refs array between 1,3,4. With an older implementation, the
	 * verifier would swap the last element with the removed element, but to
	 * maintain the stack property we need to use memmove.
	 */
	bpf_obj_drop(p);

	/* Save and restore to reset active_irq_id to 3, as the ordering is now
	 * refs=1,4,3. When restoring the linear scan will find prev_id in order
	 * as 3 instead of 4.
	 */
	bpf_local_irq_save(&flags[3]);
	bpf_local_irq_restore(&flags[3]);

	/* With the incorrect implementation, we can release flags[1], flags[2],
	 * and flags[0], i.e. in the wrong order.
	 */
	bpf_local_irq_restore(&flags[1]);
	bpf_local_irq_restore(&flags[2]);
	bpf_local_irq_restore(&flags[0]);
	return 0;
}

char _license[] SEC("license") = "GPL";
