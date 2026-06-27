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
		"r5 = *(u32 *)(r6 + 16);"
		"r1 = *(u32 *)(r6 + 0);"
		"r2 = *(u32 *)(r6 + 4);"
		"if r5 > 255 goto error;"
		"r1 += r5;"
		"r3 = r1;"
		"r1 += 2;"
		"if r1 > r2 goto error;"
		"r5 = 0;"
		"goto spill;"
	"error:"
		"r5 = -22;"
	"spill:"
		"*(u64 *)(r10 - 8) = r3;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all
	);
}

char LICENSE[] SEC("license") = "GPL";
