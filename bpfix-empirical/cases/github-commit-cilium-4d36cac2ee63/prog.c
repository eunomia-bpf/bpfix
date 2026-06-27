#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define __naked __attribute__((naked))
#define __clobber_all "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "memory"

SEC("xdp")
int __naked prog(struct xdp_md *ctx)
{
	asm volatile (
		"r6 = r1;"
		"r1 = *(u32 *)(r6 + 4);"
		"r6 = *(u32 *)(r6 + 0);"
		"w7 = w6;"
		"r0 = 2;"
		"r2 = r7;"
		"r2 += 21;"
		"if r2 > r1 goto +1;"
		"r0 = *(u8 *)(r7 + 20);"
		"exit;"
		::: __clobber_all
	);
}

char LICENSE[] SEC("license") = "GPL";
