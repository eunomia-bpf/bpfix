#define __TARGET_ARCH_x86 1
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct my {
    int value;
};

struct my_ref {
    struct my * __attribute__((btf_type_tag("kptr_ref"))) my;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, int);
    __type(value, struct my_ref);
} arr SEC(".maps");

SEC("lsm/cred_prepare")
int BPF_PROG(handle_cred_prepare, struct cred *new, const struct cred *old, gfp_t gfp, int ret)
{
    int key = 0;
    struct my_ref *val = bpf_map_lookup_elem(&arr, &key);
    if (!val)
        return 0;

    bpf_kptr_xchg(&val->my, NULL);
    return 0;
}

char _license[] SEC("license") = "GPL";
