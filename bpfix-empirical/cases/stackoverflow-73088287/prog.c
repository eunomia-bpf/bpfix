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

#define BUFFER_SIZE 2048
#define MTU 1500

struct my_buffer {
    __u32 len;
    char buf[BUFFER_SIZE + 5];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct my_buffer);
} map_my_buffer SEC(".maps");

SEC("xdp")
int WriteBuffer_main(struct xdp_md *ctx)
{
    char *data_end = (char *)(long)ctx->data_end;
    char *data = (char *)(long)ctx->data;
    char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                    sizeof(struct udphdr);
    __u32 zero = 0;
    struct my_buffer *fd;
    __u32 data_len;

    if (payload + 1 > data_end)
        return XDP_PASS;

    fd = bpf_map_lookup_elem(&map_my_buffer, &zero);
    if (!fd)
        return XDP_PASS;

    data_len = data_end - payload;
    if (data_len > MTU)
        return XDP_PASS;

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MTU; i++) {
        char *checked = payload + i + 1;
        char *read = payload + i + 16;

        if (checked > data_end)
            break;
        fd->buf[i] = *read;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
