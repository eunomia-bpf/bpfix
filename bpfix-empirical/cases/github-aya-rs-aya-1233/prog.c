#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("cgroup_skb/egress")
int prog(struct __sk_buff *skb)
{
    __u32 tgid = 0;
    void *task = (void *)bpf_get_current_task();
    bpf_probe_read(&tgid, sizeof(tgid), task + 2756);
    return tgid;
}

char LICENSE[] SEC("license") = "GPL";
