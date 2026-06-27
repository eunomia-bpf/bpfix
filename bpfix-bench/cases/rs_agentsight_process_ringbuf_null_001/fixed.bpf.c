#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

struct process_event {
    __u32 type;
    __u32 pid;
    __u32 proto;
    __u32 mark;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

SEC("tc")
int rs_agentsight_process_ringbuf_null(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct process_event *e;
    __u16 proto;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    proto = bpf_ntohs(eth->h_proto);
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;
    e->type = 1;
    e->pid = skb->mark;
    e->proto = proto;
    e->mark = 7;
    bpf_ringbuf_submit(e, 0);

    return proto == ETH_P_IP ? TC_ACT_SHOT : TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
