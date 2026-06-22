#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
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
int ringbuf_pointer_cookie(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct udphdr *udp;
    struct event *audit;
    struct event *rec;
    __u64 cookie;
    __u16 dport = 0;
    __u8 proto;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    proto = iph->protocol;
    if (proto == IPPROTO_UDP) {
        udp = (void *)iph + sizeof(*iph);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dport = bpf_ntohs(udp->dest);
    }

    audit = bpf_ringbuf_reserve(&events, sizeof(*audit), 0);
    if (!audit)
        return XDP_PASS;
    audit->mark = 3;

    rec = bpf_ringbuf_reserve(&events, sizeof(*rec), 0);
    if (!rec) {
        bpf_ringbuf_discard(audit, 0);
        return XDP_PASS;
    }

    cookie = (__u64)(long)rec;
    asm volatile("%[cookie] <<= 32; %[cookie] >>= 32" : [cookie] "+r"(cookie));

    struct event *shadow = (void *)(long)cookie;
    shadow->mark = 7;
    bpf_ringbuf_submit(audit, 0);
    bpf_ringbuf_submit(shadow, 0);

    return proto == IPPROTO_UDP && dport == 53 ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
