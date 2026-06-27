#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int prog(struct __sk_buff *ctx)
{
	asm volatile(
		"r2 = 0\n\t"
		"*(u64 *)(r10 -8) = r2\n\t"
		"r2 = 0\n\t"
		"r3 = r10\n\t"
		"r3 += -8\n\t"
		"r4 = 8\n\t"
		"call 9\n\t"
		:
		:
		: "r2", "r3", "r4", "memory");

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
