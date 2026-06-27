#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct ipv6_nat_entry_like {
	char bytes[600];
};

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int prog(void *ctx)
{
	struct ipv6_nat_entry_like tmp;
	long ret = bpf_get_current_comm(tmp.bytes, sizeof(tmp.bytes));

	return ret ? 0 : tmp.bytes[0];
}

char LICENSE[] SEC("license") = "GPL";
