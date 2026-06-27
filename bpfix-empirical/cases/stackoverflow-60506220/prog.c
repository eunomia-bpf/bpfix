#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("classifier")
int cls_prog(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;

    data_end += 1;
    return (long)data_end & 1;
}

char _license[] SEC("license") = "GPL";
