#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define DROP_NAT_NO_MAPPING 1

struct ipv6_nat_entry {
	__u32 pad;
	__u32 to_sport;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ipv6_nat_entry);
} nat_states SEC(".maps");

static __always_inline int
snat_v6_nat_handle_mapping(struct ipv6_nat_entry **state,
			   struct ipv6_nat_entry *tmp __attribute__((unused)))
{
	__u32 key = 0;

	*state = bpf_map_lookup_elem(&nat_states, &key);
	return 0;
}

SEC("tc")
int prog(struct __sk_buff *ctx)
{
	struct ipv6_nat_entry *state, tmp = {};
	int ret;

	ret = snat_v6_nat_handle_mapping(&state, &tmp);
	if (ret < 0)
		return ret;

	/* Buggy shape from the raw commit: fixed code adds if (!state). */
	return state->to_sport + ctx->mark;
}

char LICENSE[] SEC("license") = "GPL";
