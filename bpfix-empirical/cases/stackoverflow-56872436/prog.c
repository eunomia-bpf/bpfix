#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

struct mask_value {
    __u32 an_idx;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct mask_value);
} a_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    __u32 k = 0;

#pragma clang loop unroll(disable)
    for (;;) {
        struct mask_value *mask = bpf_map_lookup_elem(&a_map, &k);

        if (!mask)
            return XDP_PASS;
        if (mask->an_idx == 0)
            return XDP_DROP;
        k++;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
