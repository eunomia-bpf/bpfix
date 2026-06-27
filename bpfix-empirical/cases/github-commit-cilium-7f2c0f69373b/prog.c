#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define XDP_DROP 1
#define XDP_PASS 2

static __u32 (*helper_get_hash_recalc)(void *ctx) = (void *)34;

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	__u32 hash = helper_get_hash_recalc(ctx);

	return hash ? XDP_PASS : XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
