#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct nat_entry {
	__u32 value;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct nat_entry);
} states SEC(".maps");

__attribute__((noinline))
static int maybe_lookup(struct __sk_buff *ctx, struct nat_entry **state)
{
	__u32 key = 0;

	if (ctx->mark & 1)
		return 0;

	*state = bpf_map_lookup_elem(&states, &key);
	return 0;
}

SEC("tc")
int prog(struct __sk_buff *ctx)
{
	struct nat_entry *state;
	int ret;

	ret = maybe_lookup(ctx, &state);
	if (ret < 0)
		return ret;
	if (!state)
		return 0;

	return state->value;
}

char LICENSE[] SEC("license") = "GPL";
