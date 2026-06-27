#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define __naked __attribute__((naked))
#define __clobber_all "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "memory"

SEC("tc")
int __naked prog(struct __sk_buff *ctx)
{
	asm volatile (
		"r0 = 0;"
		"*(u64 *)(r1 + 8) = r0;"
		"exit;"
		::: __clobber_all
	);
}

char LICENSE[] SEC("license") = "GPL";
