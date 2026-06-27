#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define XDP_PASS 2

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + 14 > data_end)
		return XDP_PASS;
	if (bpf_xdp_adjust_head(ctx, -14))
		return XDP_PASS;

	return *(__u8 *)data;
}

char LICENSE[] SEC("license") = "GPL";
