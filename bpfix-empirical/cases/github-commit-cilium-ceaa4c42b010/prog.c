#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

SEC("tc")
int prog(struct __sk_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 off = 14;
	void *authhdr;

	asm volatile("" : "+m"(off));
	authhdr = data + off;
	if (authhdr + 2 > data_end)
		return TC_ACT_OK;

	*(__u32 *)(authhdr + 8) = 1;
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
