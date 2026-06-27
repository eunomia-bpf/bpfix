#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ipcache SEC(".maps");

SEC("tc")
int prog(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u64 *info = bpf_map_lookup_elem(&ipcache, &key);
    return *info;
}

char LICENSE[] SEC("license") = "GPL";
