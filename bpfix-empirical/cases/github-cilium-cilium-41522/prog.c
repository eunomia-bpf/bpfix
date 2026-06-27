#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int prog(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    return *(__u32 *)data;
}

char LICENSE[] SEC("license") = "GPL";
