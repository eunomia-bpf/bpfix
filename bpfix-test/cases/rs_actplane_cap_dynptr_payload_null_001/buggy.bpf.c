// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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

#define CAP_REQ_RELOAD_UPDATE 1001
#define CAP_REQ_RELOAD_RULE 1002
#define MAX_TAINT_UPDATES 8
#define MAX_TAINT_RULES 4
#define SCRATCH_SIZE 32

struct cap_reload_update {
    __s32 tag;
    __u32 index;
    __u32 value;
};

struct cap_reload_rule {
    __s32 tag;
    __u32 index;
    __u32 domain;
    __u32 action;
};

struct cap_scratch {
    __u8 data[SCRATCH_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cap_scratch);
} scratch_map SEC(".maps");

SEC("xdp")
int actplane_cap_dynptr_payload_null(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *bytes = data;
    struct bpf_dynptr dynptr;
    struct cap_scratch *scratch;
    __u32 key = 0;
    __u32 payload_len;
    const __s32 *tag;

    if ((void *)(bytes + 1) > data_end)
        return XDP_PASS;
    payload_len = bytes[0];
    if (payload_len > SCRATCH_SIZE)
        payload_len = SCRATCH_SIZE;

    scratch = bpf_map_lookup_elem(&scratch_map, &key);
    if (!scratch)
        return XDP_PASS;

#pragma unroll
    for (int i = 0; i < SCRATCH_SIZE; i++) {
        if (i < payload_len) {
            if ((void *)(bytes + 2 + i) > data_end)
                return XDP_PASS;
            scratch->data[i] = bytes[1 + i];
        }
    }

    if (bpf_dynptr_from_mem(scratch->data, payload_len, 0, &dynptr) < 0)
        return XDP_PASS;

    tag = bpf_dynptr_data(&dynptr, 0, sizeof(*tag));
    if (!tag)
        return XDP_PASS;

    if (*tag == CAP_REQ_RELOAD_UPDATE) {
        const struct cap_reload_update fallback = {
            .tag = CAP_REQ_RELOAD_UPDATE,
            .index = 3,
            .value = 0x55,
        };
        const struct cap_reload_update *r = &fallback;

        r = bpf_dynptr_data(&dynptr, 0, sizeof(*r));

        if (r->index >= MAX_TAINT_UPDATES)
            return XDP_PASS;
        return r->value == 0x55 ? XDP_DROP : XDP_PASS;
    }

    if (*tag == CAP_REQ_RELOAD_RULE) {
        const struct cap_reload_rule fallback = {
            .tag = CAP_REQ_RELOAD_RULE,
            .index = 2,
            .domain = 7,
            .action = 9,
        };
        const struct cap_reload_rule *r = &fallback;

        r = bpf_dynptr_data(&dynptr, 0, sizeof(*r));

        if (r->index >= MAX_TAINT_RULES)
            return XDP_PASS;
        return r->domain == 7 && r->action == 9 ? XDP_DROP : XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
