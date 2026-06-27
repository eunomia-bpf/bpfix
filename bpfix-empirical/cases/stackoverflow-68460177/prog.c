#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#undef bpf_trace_printk
static long (*bpf_trace_printk_)(const char *fmt, __u32 fmt_size, ...) =
    (void *)BPF_FUNC_trace_printk;
#define bpf_trace_printk(fmt, ...) ({ \
    char _fmt[] = fmt; \
    bpf_trace_printk_(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
})

SEC("kprobe/sys_clone")
int helloworld2(void *ctx)
{
    const char str[] = "here are some words";
    int length = sizeof(str);
    int start = 0;

#pragma unroll
    for (int i = 0; i < sizeof(str); i++) {
        if (str[i] == ' ') {
            bpf_trace_printk("%s\n", i - start, str + start);
            start = i + 1;
        }
    }
    bpf_trace_printk("%s\n", length - start, str + start);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
