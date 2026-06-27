#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define XDP_DROP 1
#define XDP_PASS 2
#define ETH_ALEN 6
#define ETH_HLEN 14

struct fib_like {
	__u8 pad;
	__u8 dmac[ETH_ALEN];
} __attribute__((packed));

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct fib_like fib = {};
	__u32 first_word;

	if (data + ETH_HLEN > data_end)
		return XDP_PASS;

	fib.dmac[0] = ctx->rx_queue_index;
	fib.dmac[1] = 1;
	fib.dmac[2] = 2;
	fib.dmac[3] = 3;
	fib.dmac[4] = 4;
	fib.dmac[5] = 5;

	asm volatile("%[word] = *(u32 *)(%[base] + 1)"
		     : [word] "=r"(first_word)
		     : [base] "r"(&fib)
		     : "memory");
	*(__u32 *)data = first_word;

	return first_word ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
