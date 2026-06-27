#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

struct v6addr_repro {
	__u32 p1;
	__u32 p2;
	__u32 p3;
	__u32 p4;
};

SEC("tc")
int unaligned_ipv6_stack_load(struct __sk_buff *ctx)
{
	struct v6addr_repro addr = {};
	__u64 word;

	addr.p1 = ctx->mark;
	addr.p2 = 2;
	addr.p3 = 3;
	addr.p4 = 4;

	asm volatile("%[word] = *(u64 *)(%[base] + 4)"
		     : [word] "=r"(word)
		     : [base] "r"(&addr)
		     : "memory");

	return word ? TC_ACT_OK : TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
