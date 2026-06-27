// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void bpf_rcu_read_lock(void) __ksym;

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

struct foo {
	struct bpf_rb_node node;
};

struct hmap_elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, struct hmap_elem);
}

hmap SEC(".maps");

private(A) struct bpf_spin_lock lock;

private(A) struct bpf_rb_root rbtree __contains(foo, node);

static bool rbless(struct bpf_rb_node *n1, const struct bpf_rb_node *n2)
{
	bpf_throw(0);
	return true;
}

SEC("?tc")
__failure __msg("function calls are not allowed while holding a lock")
int reject_with_rbtree_add_throw(void *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	bpf_spin_lock(&lock);
	bpf_rbtree_add(&rbtree, &f->node, rbless);
	bpf_spin_unlock(&lock);
	return 0;
}

char _license[] SEC("license") = "GPL";
