#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

__attribute__((noinline)) int mock_fib_lookup(void *p)
{
    return p != 0;
}

SEC("tc")
int prog(struct __sk_buff *skb)
{
    return mock_fib_lookup((void *)skb);
}

char LICENSE[] SEC("license") = "GPL";
