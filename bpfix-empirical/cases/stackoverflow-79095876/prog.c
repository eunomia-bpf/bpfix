#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_PAYLOAD_LENGTH 2000

struct ip_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 payload_length;
    char payload[MAX_PAYLOAD_LENGTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ip_event_t);
} ip_event_map SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    struct ip_event_t *event = bpf_map_lookup_elem(&ip_event_map, &key);
    if (!event)
        return 0;

    __u32 total_len = ctx->args[0] & 2047;
    if (total_len >= MAX_PAYLOAD_LENGTH)
        return 0;

    __u32 to_read = ctx->args[2] & 2047;
    if (to_read > MAX_PAYLOAD_LENGTH)
        return 0;
    if (total_len + to_read > MAX_PAYLOAD_LENGTH)
        return 0;

    if (bpf_probe_read_user(&event->payload[total_len], to_read, (void *)ctx->args[1]) < 0)
        return 0;
    return 0;
}

char _license[] SEC("license") = "GPL";
