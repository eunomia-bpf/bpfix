#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

__attribute__((noinline))
long mock_fib_lookup(void *ctx, struct bpf_fib_lookup *params,
		     int plen, __u32 flags)
{
	return params->ifindex + plen + flags + (ctx != 0);
}

SEC("tc")
int prog(struct __sk_buff *ctx)
{
	struct bpf_fib_lookup params = {};

	params.ifindex = ctx->ingress_ifindex;
	return mock_fib_lookup(ctx, &params, sizeof(params), 0);
}

char LICENSE[] SEC("license") = "GPL";
