// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define MAX_SNAPLEN 32

extern int bpf_dynptr_from_skb(struct __sk_buff *s, __u64 flags,
                               struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, __u32 offset,
                              void *buffer__opt, __u32 buffer__sz) __ksym;

struct dynptr_cfg {
    __u16 blocked_port;
    __u16 _pad1;
    __u32 snap_len;
    __u8 enable_ringbuf;
    __u8 _pad2[3];
};

struct event_hdr {
    __u64 ts_ns;
    __u32 pkt_len;
    __u16 sport;
    __u16 dport;
    __u8 drop;
    __u8 _pad;
    __u16 snap_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dynptr_cfg);
} cfg_map SEC(".maps");

SEC("tc")
int rs_tutorial_dynptr_tc_ref_leak(struct __sk_buff *ctx)
{
    __u32 key = 0;
    const struct dynptr_cfg *cfg = bpf_map_lookup_elem(&cfg_map, &key);
    struct bpf_dynptr skb_ptr;
    struct ethhdr eth_buf;
    struct iphdr ip_buf;
    struct tcphdr tcp_buf;
    const struct ethhdr *eth;
    const struct iphdr *iph;
    const struct tcphdr *tcp;
    __u32 ip_off = sizeof(*eth);
    __u32 tcp_off;
    __u32 payload_off;
    __u32 snap_len;
    __u8 payload[MAX_SNAPLEN] = {};
    __u16 sport;
    __u16 dport;
    __u8 drop = 0;
    int act = TC_ACT_OK;
    long err;

    if (!cfg)
        return TC_ACT_OK;

    if (bpf_dynptr_from_skb(ctx, 0, &skb_ptr))
        return TC_ACT_OK;

    eth = bpf_dynptr_slice(&skb_ptr, 0, &eth_buf, sizeof(eth_buf));
    if (!eth || eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    iph = bpf_dynptr_slice(&skb_ptr, ip_off, &ip_buf, sizeof(ip_buf));
    if (!iph || iph->version != 4 || iph->ihl < 5 || iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    tcp_off = ip_off + ((__u32)iph->ihl * 4);
    tcp = bpf_dynptr_slice(&skb_ptr, tcp_off, &tcp_buf, sizeof(tcp_buf));
    if (!tcp || tcp->doff < 5)
        return TC_ACT_OK;

    sport = bpf_ntohs(tcp->source);
    dport = bpf_ntohs(tcp->dest);
    if (cfg->blocked_port && dport == cfg->blocked_port) {
        drop = 1;
        act = TC_ACT_SHOT;
    }

    if (!cfg->enable_ringbuf)
        return act;

    snap_len = cfg->snap_len;
    if (snap_len > MAX_SNAPLEN)
        snap_len = MAX_SNAPLEN;

    payload_off = tcp_off + ((__u32)tcp->doff * 4);
    if (payload_off + snap_len > ctx->len)
        snap_len = 0;

    if (snap_len)
        bpf_dynptr_read(payload, snap_len, &skb_ptr, payload_off, 0);

    struct event_hdr hdr = {};
    hdr.ts_ns = bpf_ktime_get_ns();
    hdr.pkt_len = ctx->len;
    hdr.sport = sport;
    hdr.dport = dport;
    hdr.drop = drop;
    hdr.snap_len = snap_len;

    struct bpf_dynptr rb;
    err = bpf_ringbuf_reserve_dynptr(&events, sizeof(hdr) + snap_len, 0, &rb);
    if (err) {
        bpf_ringbuf_discard_dynptr(&rb, 0);
        return act;
    }

    err = bpf_dynptr_write(&rb, 0, &hdr, sizeof(hdr), 0);
    if (err) {
        bpf_ringbuf_discard_dynptr(&rb, 0);
        return act;
    }

    if (snap_len) {
        err = bpf_dynptr_write(&rb, sizeof(hdr), payload, snap_len, 0);
        if (err) {
            bpf_ringbuf_discard_dynptr(&rb, 0);
            return act;
        }
    }

    bpf_ringbuf_submit_dynptr(&rb, 0);
    return act;
}

char _license[] SEC("license") = "GPL";
