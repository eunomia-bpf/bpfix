#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define BPF_FIB_LKUP_RET_BLACKHOLE 7

struct mock_settings {
	__u8 fail_fib;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mock_settings);
} settings_map SEC(".maps");

long __noinline mock_fib_lookup(struct __sk_buff *ctx,
				struct bpf_fib_lookup *params,
				int plen, __u32 flags)
{
	__u32 key = 0;
	struct mock_settings *settings = bpf_map_lookup_elem(&settings_map, &key);

	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;
	if (settings && settings->fail_fib)
		return BPF_FIB_LKUP_RET_BLACKHOLE;
	params->ifindex = plen + flags;
	return 0;
}

SEC("tc")
int prog(struct __sk_buff *ctx)
{
	struct bpf_fib_lookup fib = {};
	__u32 key = 0;
	struct mock_settings *settings;
	long ret;

	settings = bpf_map_lookup_elem(&settings_map, &key);
	if (settings && settings->fail_fib)
		fib.ifindex = 1;
	ret = mock_fib_lookup(ctx, &fib, sizeof(fib), 0);
	return ret ? TC_ACT_OK : fib.ifindex & 1;
}

char LICENSE[] SEC("license") = "GPL";
