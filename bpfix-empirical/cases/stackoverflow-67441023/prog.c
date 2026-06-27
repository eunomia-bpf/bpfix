#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
int socket_prog(struct __sk_buff *skb)
{
    asm volatile ("r0 = *(u8 *)skb[9]" ::: "r0");
    return 0;
}

char _license[] SEC("license") = "GPL";
