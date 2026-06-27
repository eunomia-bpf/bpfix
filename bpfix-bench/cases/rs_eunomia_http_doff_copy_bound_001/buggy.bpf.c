// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#define TCP_CAPTURE_MAX 32

struct tcp_sample {
    __u32 mark;
    __u32 tcp_header_bytes;
    __u16 sport;
    __u16 dport;
    __u8 bytes[TCP_CAPTURE_MAX];
};

struct tcp_stats {
    __u64 captured;
    __u64 passed;
    __u32 last_tcp_header_bytes;
    __u16 last_dport;
    __u8 first_byte;
    __u8 last_copied;
    __u8 _pad[10];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_stats);
} stats SEC(".maps");

static __always_inline void note_pass(void)
{
    __u32 zero = 0;
    struct tcp_stats *st = bpf_map_lookup_elem(&stats, &zero);
    if (st)
        __sync_fetch_and_add(&st->passed, 1);
}

SEC("xdp")
int rs_eunomia_http_doff_copy_bound(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 ip_hdr_len;
    __u32 tcp_header_bytes;
    __u32 zero = 0;
    struct tcp_stats *st;
    struct tcp_sample *rec;

    if ((void *)(eth + 1) > data_end) {
        note_pass();
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        note_pass();
        return XDP_PASS;
    }

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        note_pass();
        return XDP_PASS;
    }
    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) {
        note_pass();
        return XDP_PASS;
    }

    ip_hdr_len = (__u32)ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip) || ip_hdr_len > 60) {
        note_pass();
        return XDP_PASS;
    }
    if ((void *)ip + ip_hdr_len > data_end) {
        note_pass();
        return XDP_PASS;
    }

    tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end) {
        note_pass();
        return XDP_PASS;
    }

    tcp_header_bytes = (__u32)tcp->doff * 4;
    if (tcp_header_bytes < sizeof(*tcp) || tcp_header_bytes > TCP_CAPTURE_MAX) {
        note_pass();
        return XDP_PASS;
    }

    rec = bpf_ringbuf_reserve(&rb, sizeof(*rec), 0);
    if (!rec) {
        note_pass();
        return XDP_PASS;
    }

    rec->mark = 0x54504344;
    rec->tcp_header_bytes = tcp_header_bytes;
    rec->sport = bpf_ntohs(tcp->source);
    rec->dport = bpf_ntohs(tcp->dest);
#pragma clang loop unroll(full)
    for (int i = 0; i < TCP_CAPTURE_MAX; i++) {
        if (i < tcp_header_bytes)
            rec->bytes[i] = *((__u8 *)tcp + i);
        else
            rec->bytes[i] = 0;
    }

    st = bpf_map_lookup_elem(&stats, &zero);
    if (st) {
        __sync_fetch_and_add(&st->captured, 1);
        st->last_tcp_header_bytes = tcp_header_bytes;
        st->last_dport = rec->dport;
        st->first_byte = rec->bytes[0];
        if (tcp_header_bytes == 32)
            st->last_copied = rec->bytes[31];
        else
            st->last_copied = rec->bytes[19];
    }

    bpf_ringbuf_submit(rec, 0);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
