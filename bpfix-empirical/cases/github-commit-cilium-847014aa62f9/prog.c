#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define XDP_DROP 1
#define XDP_PASS 2

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	__u32 data32 = ctx->data;
	__u32 data_end32 = ctx->data_end;
	void *data;
	__u8 first;

	if (data32 + 14 > data_end32)
		return XDP_PASS;

	data = (void *)(long)data32;
	first = *(__u8 *)data;

	return first == 0xff ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
