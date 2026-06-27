#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct leaf {
    __u32 fwd_idx;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct leaf);
} fwd_map SEC(".maps");

SEC("tc")
int prog(struct __sk_buff *skb)
{
    __u32 key = skb->mark;
    struct leaf *fwd_val = bpf_map_lookup_elem(&fwd_map, &key);
    return fwd_val->fwd_idx;
}

char LICENSE[] SEC("license") = "GPL";
