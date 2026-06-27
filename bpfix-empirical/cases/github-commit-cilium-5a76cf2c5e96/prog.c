#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct backend {
	__u32 address;
	__u32 port;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct backend);
} backends SEC(".maps");

SEC("cgroup/connect4")
int prog(struct bpf_sock_addr *ctx)
{
	__u32 key = ctx->user_ip4;
	struct backend *backend;
	void *field;

	backend = bpf_map_lookup_elem(&backends, &key);
	field = backend;
	asm volatile("%0 += 4" : "+r"(field));

	if (!field)
		return 0;

	return *(__u32 *)field ? 1 : 1;
}

char LICENSE[] SEC("license") = "GPL";
