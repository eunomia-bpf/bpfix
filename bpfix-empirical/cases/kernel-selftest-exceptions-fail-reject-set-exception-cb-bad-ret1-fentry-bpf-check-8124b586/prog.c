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

__noinline int exception_cb_bad_ret(u64 c)
{
	return c;
}

SEC("?fentry/bpf_check")
__exception_cb(exception_cb_bad_ret)
__failure __msg("At program exit the register R0 has unknown scalar value should")
int reject_set_exception_cb_bad_ret1(void *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
