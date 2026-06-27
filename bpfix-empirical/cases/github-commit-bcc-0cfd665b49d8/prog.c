#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct trace_event_raw_test {
    __u64 pad;
    __u32 data_loc_name;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int prog(struct trace_event_raw_test *args)
{
    char dst[32];
    short off = args->data_loc_name & 0xffff;
    short len = args->data_loc_name >> 16;

    bpf_probe_read_kernel(dst, len, (char *)args + off);
    return dst[0];
}

char LICENSE[] SEC("license") = "GPL";
