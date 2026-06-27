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
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct event {
    __u32 mark;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("xdp")
int ringbuf_two_record_cookie(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u8 proto = 0;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    proto = iph->protocol;

    struct event *audit = bpf_ringbuf_reserve(&events, sizeof(*audit), 0);
    if (!audit)
        return XDP_PASS;
    audit->mark = 3;

    struct event *rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
    if (!rec) {
        bpf_ringbuf_discard(audit, 0);
        return XDP_PASS;
    }

    rec->mark = proto == IPPROTO_UDP ? 7 : 11;

    __u64 cookie = (__u64)(long)rec;
    asm volatile("%[cookie] <<= 32; %[cookie] >>= 32" : [cookie] "+r"(cookie));
    rec = (struct event *)(long)cookie;

    bpf_ringbuf_submit(audit, 0);
    bpf_ringbuf_submit(rec, 0);
    return proto == IPPROTO_UDP ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
