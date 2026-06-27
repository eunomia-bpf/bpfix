#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define DROP_INVALID 1

struct remote_endpoint_info {
	__u32 sec_identity;
	__u32 tunnel_endpoint;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct remote_endpoint_info);
} endpoints SEC(".maps");

static __always_inline int set_ipsec_encrypt(__u32 sec_identity)
{
	return sec_identity ? TC_ACT_OK : DROP_INVALID;
}

SEC("tc")
int prog(struct __sk_buff *ctx)
{
	__u32 key = ctx->mark;
	struct remote_endpoint_info *info;
	__u32 tunnel_endpoint;

	info = bpf_map_lookup_elem(&endpoints, &key);
	tunnel_endpoint = ctx->ifindex;

	if (tunnel_endpoint)
		return set_ipsec_encrypt(info->sec_identity);

	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
