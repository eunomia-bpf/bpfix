#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define __naked __attribute__((naked))
#define __imm(name) [name] "i" (name)
#define __clobber_all "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "memory"

SEC("tc")
int __naked prog(struct __sk_buff *ctx)
{
	asm volatile (
		"r6 = r1;"
		"r9 = 0;"
		"*(u64 *)(r10 - 8) = r9;"
		"*(u64 *)(r10 - 16) = r9;"
		"*(u64 *)(r10 - 24) = r9;"
		"*(u64 *)(r10 - 32) = r9;"
		"*(u64 *)(r10 - 40) = r9;"
		"*(u64 *)(r10 - 48) = r9;"
		"r8 = *(u32 *)(r6 + 0);"
		"if r8 == 0 goto tcp_lookup;"

	"udp_lookup:"
		"r1 = r6;"
		"r2 = r10;"
		"r2 += -48;"
		"r3 = 36;"
		"r4 = -1;"
		"r5 = 0;"
		"call %[bpf_sk_lookup_udp];"
		"if r0 == 0 goto out;"
		"goto common;"

	"tcp_lookup:"
		"r1 = r6;"
		"r2 = r10;"
		"r2 += -48;"
		"r3 = 36;"
		"r4 = -1;"
		"r5 = 0;"
		"call %[bpf_skc_lookup_tcp];"
		"if r0 == 0 goto out;"

	"common:"
		"r7 = *(u32 *)(r0 + 4);"
		"r1 = r0;"
		"call %[bpf_sk_release];"
	"out:"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_sk_lookup_udp),
		  __imm(bpf_skc_lookup_tcp),
		  __imm(bpf_sk_release)
		: __clobber_all
	);
}

char LICENSE[] SEC("license") = "GPL";
