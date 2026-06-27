#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 4096);
} heap SEC(".maps");

static __noinline __u32 hash(unsigned char *str)
{
    __u32 h = 5381;

    for (int i = 0; i < 4097; i++) {
        unsigned char c = *str++;

        if (!c)
            break;
        h = h * 33 + c;
    }
    return h;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_exec(struct trace_event_raw_sys_enter *ctx)
{
    __u32 id = 0;
    unsigned char *map_val = bpf_map_lookup_elem(&heap, &id);
    if (!map_val)
        return 0;

    return hash(map_val);
}

char _license[] SEC("license") = "GPL";
