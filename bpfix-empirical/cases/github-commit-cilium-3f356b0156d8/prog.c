#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

SEC("tc")
int stale_packet_pointer_after_ctx_write(struct __sk_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4 = data;
	__u8 zero = 0;

	if ((void *)(ip4 + 1) > data_end)
		return TC_ACT_OK;

	if (bpf_skb_store_bytes(ctx, 0, &zero, sizeof(zero), 0) < 0)
		return TC_ACT_OK;

	if (ip4->protocol)
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
