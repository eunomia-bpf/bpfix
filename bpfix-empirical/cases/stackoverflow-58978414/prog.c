#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 12);
} test SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int compare_map_value(void *ctx)
{
	__u32 key0 = 0;
	void *comparer = bpf_map_lookup_elem(&test, &key0);

	bpf_map_update_elem(&test, &key0, comparer, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
