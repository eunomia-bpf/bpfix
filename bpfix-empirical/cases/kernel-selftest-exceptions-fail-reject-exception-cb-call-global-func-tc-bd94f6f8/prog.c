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

__noinline int exception_cb1(u64 c)
{
	return c;
}

__noinline int global_func(struct __sk_buff *ctx)
{
	return exception_cb1(ctx->tstamp);
}

SEC("?tc")
__exception_cb(exception_cb1)
__failure __msg("cannot call exception cb directly")
int reject_exception_cb_call_global_func(struct __sk_buff *ctx)
{
	return global_func(ctx);
}

char _license[] SEC("license") = "GPL";
