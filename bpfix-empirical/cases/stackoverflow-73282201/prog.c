#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct data_t {
    __u8 data[4096];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct data_t);
} storage SEC(".maps");

SEC("kprobe/vfs_read")
int count_bytes(struct pt_regs *ctx)
{
    __u32 key = 0;
    struct data_t *value = bpf_map_lookup_elem(&storage, &key);

    if (!value)
        return 0;

    volatile __u8 byte = value->data[4096];
    return byte;
}

char _license[] SEC("license") = "GPL";
