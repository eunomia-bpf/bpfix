#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_FLAGS_LEN 20

struct value {
    char flags[MAX_FLAGS_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32);
    __type(key, __u8);
    __type(value, struct value);
} output_map SEC(".maps");

SEC("classifier")
int tc_ingress(struct __sk_buff *skb)
{
    __u8 key = 1;
    struct value *value = bpf_map_lookup_elem(&output_map, &key);

    if (!value)
        return 0;

    __u32 idx = skb->len;
    if (idx < 64)
        value->flags[idx] = 1;
    return 0;
}

char _license[] SEC("license") = "GPL";
