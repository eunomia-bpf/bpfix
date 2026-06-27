#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct remote_endpoint_info {
	__u32 sec_label;
	__u32 tunnel_endpoint;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct remote_endpoint_info);
} ipcache SEC(".maps");

SEC("tc")
int prog(struct __sk_buff *ctx)
{
	__u32 key = ctx->mark;
	struct remote_endpoint_info *info;
	__u32 src_identity = 2;

	info = bpf_map_lookup_elem(&ipcache, &key);
	if (!info) {
		asm volatile("%0 = *(u32 *)(%1 + 0)"
			     : "=r"(src_identity)
			     : "r"(info)
			     : "memory");
	}

	return src_identity == 0 ? TC_ACT_SHOT : TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
