#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define PATH_SEGMENT_LEN 255
typedef unsigned char path_segment[PATH_SEGMENT_LEN];

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, PATH_SEGMENT_LEN);
} cpu_buffer SEC(".maps");

SEC("tp/syscalls/sys_enter_nanosleep")
int handle(struct trace_event_raw_sys_enter *ctx)
{
    __u32 j = 0;
    path_segment *a = bpf_map_lookup_elem(&cpu_buffer, &j);
    if (!a)
        return 0;

    unsigned char x = *a[2];
    return x;
}

char _license[] SEC("license") = "GPL";
