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
		"r6 = r1;"
		"r7 = *(u32 *)(r6 + 76);"
		"r8 = *(u32 *)(r6 + 80);"
		"r1 = r7;"
		"r1 += 33;"
		"if r1 > r8 goto bad_path;"
		"goto read_nexthdr;"
	"bad_path:"
		"r7 = 0;"
	"read_nexthdr:"
		"r1 = *(u8 *)(r7 + 32);"
		"r0 = r1;"
		"exit;"
		::: __clobber_all
	);
}

char LICENSE[] SEC("license") = "GPL";
