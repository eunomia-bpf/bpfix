#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct ipv6_ct_tuple_like {
	char bytes[320];
};

struct ipv6_nat_target_like {
	char bytes[280];
};

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int oversized_nat_scratch(void *ctx)
{
	struct ipv6_ct_tuple_like tuple;
	struct ipv6_nat_target_like target;
	long ret;

	ret = bpf_get_current_comm(tuple.bytes, sizeof(tuple.bytes));
	if (ret)
		return 0;

	ret = bpf_get_current_comm(target.bytes, sizeof(target.bytes));
	if (ret)
		return 0;

	return tuple.bytes[0] + target.bytes[0];
}

char LICENSE[] SEC("license") = "GPL";
