#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#define SERVER_NAME_EXTENSION 0

struct extension {
    __u16 type;
    __u16 len;
} __attribute__((packed));

SEC("xdp")
int collect_ips_prog(struct xdp_md *ctx)
{
    char *data_end = (char *)(long)ctx->data_end;
    char *data = (char *)(long)ctx->data;
    __u16 extension_methods_len;

    if (data + sizeof(__u16) > data_end)
        return XDP_PASS;

    extension_methods_len = bpf_ntohs(*(__u16 *)data);
    data += sizeof(__u16);

#pragma clang loop unroll(disable)
    for (int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
        struct extension *ext;
        __u16 ext_len;

        if (data + sizeof(struct extension) > data_end)
            return XDP_PASS;

        ext = (struct extension *)data;
        data += sizeof(struct extension);

        if (ext->type == SERVER_NAME_EXTENSION)
            return XDP_DROP;

        ext_len = bpf_ntohs(ext->len);
        if (ext_len > 3000)
            return XDP_PASS;

        if (data + ext_len > data_end)
            return XDP_PASS;

        data += ext_len;
        i += ext_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
