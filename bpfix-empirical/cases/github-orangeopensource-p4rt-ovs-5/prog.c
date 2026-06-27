#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pipe_downstream_tbl SEC(".maps");

SEC("tc")
int prog(struct __sk_buff *skb)
{
    __u32 key = skb->mark;
    __u32 *value = bpf_map_lookup_elem(&pipe_downstream_tbl, &key);
    if (!value)
        return 0;

    return *(__u64 *)value;
}

char LICENSE[] SEC("license") = "GPL";
