#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
    const struct inet_sock *inet = (const struct inet_sock *)sk;
    __u16 sport = inet->inet_sport;
    __u32 saddr = inet->inet_saddr;

    return sport + saddr;
}

char LICENSE[] SEC("license") = "GPL";
