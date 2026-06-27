#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ETH_HLEN 14
#define IPV6_HLEN 40
#define MAX_PACKET_LENGTH 1024

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[MAX_PACKET_LENGTH]);
} packet_data_map SEC(".maps");

SEC("tc")
int prog(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u8 *packet_data_buffer = bpf_map_lookup_elem(&packet_data_map, &key);
    if (!packet_data_buffer)
        return 0;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 data_length = (__u32)(data_end - (data + ETH_HLEN + IPV6_HLEN));

    data_length &= 1023;
    int tmp = MAX_PACKET_LENGTH - data_length;
    if (tmp < 0)
        return 0;

    return bpf_skb_load_bytes(skb, ETH_HLEN + IPV6_HLEN,
                              packet_data_buffer, data_length);
}

char LICENSE[] SEC("license") = "GPL";
