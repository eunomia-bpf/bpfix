#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int prog(struct __sk_buff *skb)
{
    __u8 buf[32];
    __u32 len = skb->len & 31;
    return bpf_skb_load_bytes(skb, 0, buf, len);
}

char LICENSE[] SEC("license") = "GPL";
