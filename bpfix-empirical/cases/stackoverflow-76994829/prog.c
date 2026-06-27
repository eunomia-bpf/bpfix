#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define PID_LEN_MAX 8
#define XDP_PASS 2

typedef __u32 u32;

struct target_d_name {
	unsigned long len;
	char name[PID_LEN_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, u32);
	__type(value, sizeof(struct target_d_name));
} map_d_name_tgts SEC(".maps");

SEC("xdp")
int write_name_from_array_map(struct xdp_md *ctx)
{
	u32 index = 0;
	struct target_d_name *current_d_name;

	current_d_name = bpf_map_lookup_elem(&map_d_name_tgts, &index);
	if (!current_d_name)
		return XDP_PASS;

#pragma clang loop unroll(full)
	for (int i = 0; i < PID_LEN_MAX; i++)
		current_d_name->name[i] = 'u';

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
